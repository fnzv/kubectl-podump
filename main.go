package main

import (
	"context"
	"crypto/sha1"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/remotecommand"
)

const version = "1.4.4"

type PodStats struct {
	TotalBytes int64
	TCPBytes   int64
	UDPBytes   int64
	ICMPBytes  int64
	RemoteIPs  map[string]*int64
}

var (
	statsMap   = make(map[string]*PodStats)
	statsMutex sync.Mutex
	startTime  time.Time
	ansiColors = []string{"\033[32m", "\033[33m", "\033[34m", "\033[35m", "\033[36m", "\033[31m"}
	portRegex  = regexp.MustCompile(`(\.(80|443|3306|5432|6379|8080|2379|9090|53)\b)`)
	ipRegex    = regexp.MustCompile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`)
)

func boolPtr(b bool) *bool { return &b }

func main() {
	nsFlag := flag.String("n", "", "Namespace (defaults to current context)")
	pcapFlag := flag.Bool("pcap", false, "Output raw PCAP binary")
	debugFlag := flag.Bool("debug", false, "Force Standalone Debug Pod")
	labelFlag := flag.String("l", "", "Label selector")
	helpFlag := flag.Bool("h", false, "Show help")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "  _____          _                \n")
		fmt.Fprintf(os.Stderr, " |  __ \\        | |               \n")
		fmt.Fprintf(os.Stderr, " | |__) |__   __| |_   _ _ __ ___ \n")
		fmt.Fprintf(os.Stderr, " |  ___/ _ \\ / _` | | | | '_ ` _ \\ \n")
		fmt.Fprintf(os.Stderr, " | |  | (_) | (_| | |_| | | | | | |\n")
		fmt.Fprintf(os.Stderr, " |_|   \\___/ \\__,_|_| |_| |_| |_|\n")
		fmt.Fprintf(os.Stderr, "         v%s - Kubernetes Sniffer\n\n", version)
		fmt.Fprintf(os.Stderr, "Usage: podump [options] [pod-name-search] [tcpdump-filters]\n")
		flag.PrintDefaults()
		os.Exit(0)
	}

	cleanArgs := []string{os.Args[0]}
	for _, arg := range os.Args[1:] {
		if arg == "-debug" || arg == "--debug" { *debugFlag = true } else if arg == "-h" || arg == "--help" { flag.Usage() } else { cleanArgs = append(cleanArgs, arg) }
	}
	os.Args = cleanArgs
	flag.Parse()

	args := flag.Args()
	if *helpFlag || (len(args) < 1 && *labelFlag == "") { flag.Usage() }

	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, &clientcmd.ConfigOverrides{})
	namespace, _, _ := kubeConfig.Namespace()
	if *nsFlag != "" { namespace = *nsFlag }
	config, _ := kubeConfig.ClientConfig()
	clientset, _ := kubernetes.NewForConfig(config)
	
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var targetPods []corev1.Pod
	listOpts := metav1.ListOptions{LabelSelector: *labelFlag}
	allPods, _ := clientset.CoreV1().Pods(namespace).List(ctx, listOpts)
	for _, p := range allPods.Items {
		if len(args) > 0 {
			if strings.Contains(p.Name, args[0]) { targetPods = append(targetPods, p) }
		} else { targetPods = append(targetPods, p) }
	}

	if len(targetPods) == 0 {
		fmt.Fprintf(os.Stderr, "❌ No pods found.\n")
		os.Exit(1)
	}

	tcpdumpCmd := []string{"tcpdump", "-i", "any", "--immediate-mode", "-l", "-n"}
	if *pcapFlag {
		tcpdumpCmd = []string{"tcpdump", "-i", "any", "--immediate-mode", "-U", "-w", "-"}
	}
	if len(args) > 1 { tcpdumpCmd = append(tcpdumpCmd, args[1:]...) }

	var wg sync.WaitGroup
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	fmt.Fprintf(os.Stderr, "📡 Sniffing %d pod(s)...\n", len(targetPods))
	startTime = time.Now()

	for i, pod := range targetPods {
		color := ansiColors[i%len(ansiColors)]
		wg.Add(1)
		go func(p corev1.Pod, c string) {
			defer wg.Done()
			var pName, cName string
			if *debugFlag {
				cName = "sniffer"
				pName = createDebugPod(ctx, clientset, namespace, &p, tcpdumpCmd)
				defer func() {
					grace := int64(0)
					clientset.CoreV1().Pods(namespace).Delete(context.Background(), pName, metav1.DeleteOptions{GracePeriodSeconds: &grace})
				}()
			} else {
				pName = p.Name
				cName = injectEphemeral(ctx, clientset, namespace, &p, tcpdumpCmd)
			}
			streamPackets(ctx, clientset, config, namespace, pName, cName, p.Name, c, *pcapFlag)
		}(pod, color)
	}

	go func() {
		<-sigChan
		fmt.Fprintf(os.Stderr, "\n[Stop] Stopping captures...\n")
		cancel()
	}()

	wg.Wait()
	printSummary()
}

func printSummary() {
	duration := time.Since(startTime).Seconds()
	if duration < 1 { duration = 1 }
	fmt.Fprintf(os.Stderr, "\n📊 --- TRAFFIC SUMMARY (%ds) ---\n", int(duration))
	
	statsMutex.Lock()
	defer statsMutex.Unlock()

	for podName, s := range statsMap {
		total := float64(s.TotalBytes) / 1024
		fmt.Fprintf(os.Stderr, "\n📦 POD: %s (Total: %.2f KB)\n", podName, total)
		fmt.Fprintf(os.Stderr, "   ├─ TCP:  %.1f KB | UDP: %.1f KB | ICMP: %.1f KB\n", 
			float64(s.TCPBytes)/1024, float64(s.UDPBytes)/1024, float64(s.ICMPBytes)/1024)
		
		if len(s.RemoteIPs) > 0 {
			fmt.Fprintf(os.Stderr, "   └─ TOP TALKERS (IPs):\n")
			type ipEntry struct { ip string; val int64 }
			var ips []ipEntry
			for ip, val := range s.RemoteIPs { ips = append(ips, ipEntry{ip, *val}) }
			sort.Slice(ips, func(i, j int) bool { return ips[i].val > ips[j].val })

			for count, e := range ips {
				if count >= 3 { break }
				fmt.Fprintf(os.Stderr, "      • %-15s %8.1f KB\n", e.ip, float64(e.val)/1024)
			}
		}
	}
	fmt.Fprintf(os.Stderr, "\n------------------------------------------\n")
}

func streamPackets(ctx context.Context, clientset *kubernetes.Clientset, config *rest.Config, ns, pod, container, originalName, color string, isPcap bool) {
	if container == "" { return }
	
	statsMutex.Lock()
	statsMap[originalName] = &PodStats{RemoteIPs: make(map[string]*int64)}
	statsMutex.Unlock()

	for {
		select {
		case <-ctx.Done(): return
		default:
			p, _ := clientset.CoreV1().Pods(ns).Get(ctx, pod, metav1.GetOptions{})
			if p != nil {
				for _, s := range append(p.Status.ContainerStatuses, p.Status.EphemeralContainerStatuses...) {
					if s.Name == container && s.State.Running != nil { goto ready }
				}
			}
			time.Sleep(1 * time.Second)
		}
	}

ready:
	req := clientset.CoreV1().RESTClient().Post().Resource("pods").Namespace(ns).Name(pod).SubResource("attach").
		VersionedParams(&corev1.PodAttachOptions{Container: container, Stdout: true, Stderr: true}, scheme.ParameterCodec)

	exec, _ := remotecommand.NewSPDYExecutor(config, "POST", req.URL())
	
	pw := &prefixWriter{
		w:        os.Stdout,
		prefix:   fmt.Sprintf("%s[%s]\033[0m ", color, originalName),
		podName:  originalName,
		isPcap:   isPcap,
	}

	_ = exec.StreamWithContext(ctx, remotecommand.StreamOptions{Stdout: pw, Stderr: os.Stderr})
}

type prefixWriter struct {
	w       io.Writer
	prefix  string
	podName string
	isPcap  bool
}

func (pw *prefixWriter) Write(p []byte) (n int, err error) {
	s := statsMap[pw.podName]
	
	if pw.isPcap {
		atomic.AddInt64(&s.TotalBytes, int64(len(p)))
		return pw.w.Write(p)
	}

	lines := strings.Split(string(p), "\n")
	for _, line := range lines {
		if line == "" { continue }
		lineLen := int64(len(line))
		atomic.AddInt64(&s.TotalBytes, lineLen)

		// SMART PROTOCOL DETECTION
		// 1. TCP: Look for Flags [ ] or literal TCP
		if strings.Contains(line, "Flags [") || strings.Contains(line, "TCP") {
			atomic.AddInt64(&s.TCPBytes, lineLen)
		} else if strings.Contains(line, "UDP") || strings.Contains(line, "proto 17") || strings.Contains(line, "ip-proto-17") {
			// 2. UDP: Look for literal UDP or IP protocol 17
			atomic.AddInt64(&s.UDPBytes, lineLen)
		} else if strings.Contains(line, "ICMP") || strings.Contains(line, "proto 1") {
			// 3. ICMP: Look for literal ICMP or IP protocol 1
			atomic.AddInt64(&s.ICMPBytes, lineLen)
		}

		// IP EXTRACTION
		foundIPs := ipRegex.FindAllString(line, -1)
		for _, ip := range foundIPs {
			statsMutex.Lock()
			if _, ok := s.RemoteIPs[ip]; !ok {
				var v int64 = 0
				s.RemoteIPs[ip] = &v
			}
			// Distribute the line length among found IPs
			atomic.AddInt64(s.RemoteIPs[ip], lineLen/int64(len(foundIPs)))
			statsMutex.Unlock()
		}

		highlighted := portRegex.ReplaceAllString(line, "\033[1;31m$1\033[0m")
		fmt.Fprintf(pw.w, "%s%s\n", pw.prefix, highlighted)
	}
	return len(p), nil
}

func injectEphemeral(ctx context.Context, clientset *kubernetes.Clientset, ns string, target *corev1.Pod, cmd []string) string {
	h := sha1.New()
	io.WriteString(h, strings.Join(cmd, ""))
	io.WriteString(h, fmt.Sprintf("%d", time.Now().UnixNano()))
	cName := fmt.Sprintf("pd-%x", h.Sum(nil))[:12]
	ephemeral := corev1.EphemeralContainer{
		EphemeralContainerCommon: corev1.EphemeralContainerCommon{
			Name: cName, Image: "ghcr.io/fnzv/podump", Command: cmd,
			ImagePullPolicy: corev1.PullAlways,
			SecurityContext: &corev1.SecurityContext{
				Privileged: boolPtr(true),
				Capabilities: &corev1.Capabilities{Add: []corev1.Capability{"NET_ADMIN", "NET_RAW"}},
			},
		},
	}
	latest, _ := clientset.CoreV1().Pods(ns).Get(ctx, target.Name, metav1.GetOptions{})
	latest.Spec.EphemeralContainers = append(latest.Spec.EphemeralContainers, ephemeral)
	_, err := clientset.CoreV1().Pods(ns).UpdateEphemeralContainers(ctx, latest.Name, latest, metav1.UpdateOptions{})
	if err != nil { return "" }
	return cName
}

func createDebugPod(ctx context.Context, clientset *kubernetes.Clientset, ns string, target *corev1.Pod, cmd []string) string {
	pName := fmt.Sprintf("pd-dbg-%x", sha1.Sum([]byte(fmt.Sprintf("%s%d", target.Name, time.Now().UnixNano()))))[:18]
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: pName, Namespace: ns, Labels: map[string]string{"podump-owner": "cli"}},
		Spec: corev1.PodSpec{
			NodeName: target.Spec.NodeName, HostNetwork: true, RestartPolicy: corev1.RestartPolicyNever,
			Containers: []corev1.Container{{
				Name: "sniffer", Image: "ghcr.io/fnzv/podump", Command: cmd,
				SecurityContext: &corev1.SecurityContext{Privileged: boolPtr(true)},
			}},
		},
	}
	clientset.CoreV1().Pods(ns).Create(ctx, pod, metav1.CreateOptions{})
	return pName
}