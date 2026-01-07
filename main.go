package main

import (
	"context"
	"crypto/sha1"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
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

const version = "1.4.0"

// Global for tracking stats and colors
var (
	stats      = make(map[string]*int64)
	statsMutex sync.Mutex
	ansiColors = []string{"\033[32m", "\033[33m", "\033[34m", "\033[35m", "\033[36m", "\033[31m"} 
)

func boolPtr(b bool) *bool { return &b }

func main() {
	// 1. Define Flags
	nsFlag := flag.String("n", "", "Namespace (defaults to current context)")
	pcapFlag := flag.Bool("pcap", false, "Output raw PCAP binary (saves to files if multiple pods matched)")
	debugFlag := flag.Bool("debug", false, "Force Standalone Debug Pod (bypasses security restrictions)")
	labelFlag := flag.String("l", "", "Label selector (e.g. app=nginx)")
	helpFlag := flag.Bool("h", false, "Show this help menu")

	// Custom Usage/Help Message
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "  _____          _                \n")
		fmt.Fprintf(os.Stderr, " |  __ \\        | |               \n")
		fmt.Fprintf(os.Stderr, " | |__) |__   __| |_   _ _ __ ___ \n")
		fmt.Fprintf(os.Stderr, " |  ___/ _ \\ / _` | | | | '_ ` _ \\ \n")
		fmt.Fprintf(os.Stderr, " | |  | (_) | (_| | |_| | | | | | |\n")
		fmt.Fprintf(os.Stderr, " |_|   \\___/ \\__,_|_| |_| |_| |_|\n")
		fmt.Fprintf(os.Stderr, "         v%s - Kubernetes Sniffer\n\n", version)

		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  podump [options] [pod-name-search] [tcpdump-filters]\n\n")

		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()

		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  # Sniff multiple pods by label and save separate PCAPs\n")
		fmt.Fprintf(os.Stderr, "  podump -l app=nginx -pcap\n\n")

		fmt.Fprintf(os.Stderr, "  # Sniff specific port on all pods matching 'api'\n")
		fmt.Fprintf(os.Stderr, "  podump api port 8080\n\n")

		fmt.Fprintf(os.Stderr, "  # Stream a single pod directly to Wireshark\n")
		fmt.Fprintf(os.Stderr, "  podump -pcap my-pod | wireshark -k -i -\n\n")

		os.Exit(0)
	}

	// Bulletproof Argument Parsing
	cleanArgs := []string{os.Args[0]}
	for _, arg := range os.Args[1:] {
		if arg == "-debug" || arg == "--debug" {
			*debugFlag = true
		} else if arg == "-h" || arg == "--help" {
			flag.Usage()
		} else {
			cleanArgs = append(cleanArgs, arg)
		}
	}
	os.Args = cleanArgs
	flag.Parse()

	args := flag.Args()
	if *helpFlag || (len(args) < 1 && *labelFlag == "") {
		flag.Usage()
	}

	// 2. K8s Config Setup
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, &clientcmd.ConfigOverrides{})
	namespace, _, _ := kubeConfig.Namespace()
	if *nsFlag != "" { namespace = *nsFlag }
	config, _ := kubeConfig.ClientConfig()
	clientset, _ := kubernetes.NewForConfig(config)
	
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 3. Discovery Logic
	var targetPods []corev1.Pod
	listOpts := metav1.ListOptions{LabelSelector: *labelFlag}
	allPods, err := clientset.CoreV1().Pods(namespace).List(ctx, listOpts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ List Error: %v\n", err)
		os.Exit(1)
	}

	for _, p := range allPods.Items {
		if len(args) > 0 {
			if strings.Contains(p.Name, args[0]) { targetPods = append(targetPods, p) }
		} else { targetPods = append(targetPods, p) }
	}

	if len(targetPods) == 0 {
		fmt.Fprintf(os.Stderr, "❌ No pods found matching criteria.\n")
		os.Exit(1)
	}

	// 4. Handle Multi-Pod PCAP Storage
	pcapDir := ""
	if *pcapFlag && len(targetPods) > 1 {
		pcapDir = fmt.Sprintf("captures_%s", time.Now().Format("20060102_150405"))
		os.MkdirAll(pcapDir, 0755)
		fmt.Fprintf(os.Stderr, "📂 Multiple pods detected. Saving PCAPs to: %s/\n", pcapDir)
	}

	// 5. Build Command
	tcpdumpFilters := []string{}
	if len(args) > 1 { tcpdumpFilters = args[1:] }
	tcpdumpCmd := []string{"tcpdump", "-i", "any", "--immediate-mode"}
	if *pcapFlag { tcpdumpCmd = append(tcpdumpCmd, "-U", "-w", "-") } else { tcpdumpCmd = append(tcpdumpCmd, "-l", "-n") }
	tcpdumpCmd = append(tcpdumpCmd, tcpdumpFilters...)

	// 6. Multicast Execution
	var wg sync.WaitGroup
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	fmt.Fprintf(os.Stderr, "📡 Starting capture on %d pod(s). Press Ctrl+C to stop.\n", len(targetPods))

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
			streamPackets(ctx, clientset, config, namespace, pName, cName, p.Name, *pcapFlag, pcapDir, c)
		}(pod, color)
	}

	go func() {
		<-sigChan
		fmt.Fprintf(os.Stderr, "\n[Stop] Terminating all captures...\n")
		cancel()
	}()

	wg.Wait()
	printSummary()
}

func printSummary() {
	fmt.Fprintf(os.Stderr, "\n📊 --- CAPTURE SUMMARY ---\n")
	fmt.Fprintf(os.Stderr, "%-40s %-15s\n", "POD NAME", "DATA CAPTURED")
	fmt.Fprintf(os.Stderr, "%-40s %-15s\n", "--------", "-------------")
	
	statsMutex.Lock()
	defer statsMutex.Unlock()
	for name, bytes := range stats {
		size := float64(*bytes)
		unit := "B"
		if size > 1024*1024 { size = size / (1024 * 1024); unit = "MB"
		} else if size > 1024 { size = size / 1024; unit = "KB" }
		fmt.Fprintf(os.Stderr, "%-40s %.2f %s\n", name, size, unit)
	}
	fmt.Fprintf(os.Stderr, "--------------------------\n")
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

func streamPackets(ctx context.Context, clientset *kubernetes.Clientset, config *rest.Config, ns, pod, container, originalName string, isPcap bool, pcapDir string, color string) {
	if container == "" { return }
	
	statsMutex.Lock()
	var bCount int64 = 0
	stats[originalName] = &bCount
	statsMutex.Unlock()

	for {
		select {
		case <-ctx.Done(): return
		default:
			p, err := clientset.CoreV1().Pods(ns).Get(ctx, pod, metav1.GetOptions{})
			if err == nil {
				statuses := append(p.Status.ContainerStatuses, p.Status.EphemeralContainerStatuses...)
				for _, s := range statuses {
					if s.Name == container && s.State.Running != nil { goto ready }
				}
			}
			time.Sleep(1 * time.Second)
		}
	}

ready:
	fmt.Fprintf(os.Stderr, "%s🚀 [%s] Active!\033[0m\n", color, originalName)
	req := clientset.CoreV1().RESTClient().Post().Resource("pods").Namespace(ns).Name(pod).SubResource("attach").
		VersionedParams(&corev1.PodAttachOptions{Container: container, Stdout: true, Stderr: true}, scheme.ParameterCodec)

	exec, _ := remotecommand.NewSPDYExecutor(config, "POST", req.URL())

	var out io.Writer
	if isPcap && pcapDir != "" {
		f, _ := os.Create(filepath.Join(pcapDir, fmt.Sprintf("%s.pcap", originalName)))
		defer f.Close()
		out = f
	} else if isPcap { out = os.Stdout
	} else { out = &prefixWriter{w: os.Stdout, prefix: fmt.Sprintf("%s[%s]\033[0m ", color, originalName)} }

	countedOut := &countWriter{w: out, count: stats[originalName]}
	_ = exec.StreamWithContext(ctx, remotecommand.StreamOptions{Stdout: countedOut, Stderr: os.Stderr})
}

type countWriter struct {
	w     io.Writer
	count *int64
}

func (cw *countWriter) Write(p []byte) (n int, err error) {
	atomic.AddInt64(cw.count, int64(len(p)))
	return cw.w.Write(p)
}

type prefixWriter struct {
	w      io.Writer
	prefix string
}

func (pw *prefixWriter) Write(p []byte) (n int, err error) {
	lines := strings.Split(string(p), "\n")
	for i, line := range lines {
		if line == "" && i == len(lines)-1 { continue }
		fmt.Fprintf(pw.w, "%s%s\n", pw.prefix, line)
	}
	return len(p), nil
}