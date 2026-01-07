package main

import (
	"context"
	"crypto/sha1"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
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

const version = "1.2.4"

func boolPtr(b bool) *bool { return &b }

func main() {
	nsFlag := flag.String("n", "", "Namespace")
	pcapFlag := flag.Bool("pcap", false, "Output PCAP binary")
	debugFlag := flag.Bool("debug", false, "Force Standalone Debug Pod")

	// Scan for -debug anywhere in the command line
	cleanArgs := []string{os.Args[0]}
	for _, arg := range os.Args[1:] {
		if arg == "-debug" || arg == "--debug" {
			*debugFlag = true
		} else {
			cleanArgs = append(cleanArgs, arg)
		}
	}
	os.Args = cleanArgs
	flag.Parse()

	args := flag.Args()
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: podump [options] <pod-name-search> [tcpdump-filters]\n")
		os.Exit(1)
	}

	searchTerm := args[0]
	tcpdumpFilters := args[1:]

	// K8s Config
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, &clientcmd.ConfigOverrides{})
	namespace, _, _ := kubeConfig.Namespace()
	if *nsFlag != "" { namespace = *nsFlag }
	if namespace == "" { namespace = "default" }

	config, _ := kubeConfig.ClientConfig()
	clientset, _ := kubernetes.NewForConfig(config)
	ctx, cancel := context.WithCancel(context.Background())

	// Search
	fmt.Fprintf(os.Stderr, "🔍 Looking for: %s in %s\n", searchTerm, namespace)
	pods, err := clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ List Error: %v\n", err)
		os.Exit(1)
	}

	var targetPod *corev1.Pod
	for _, p := range pods.Items {
		if strings.Contains(p.Name, searchTerm) {
			targetPod = &p
			break
		}
	}

	if targetPod == nil {
		fmt.Fprintf(os.Stderr, "❌ Pod not found matching: %s\n", searchTerm)
		os.Exit(1)
	}

	// Command
	tcpdumpCmd := []string{"tcpdump", "-i", "any", "--immediate-mode"}
	if *pcapFlag {
		tcpdumpCmd = append(tcpdumpCmd, "-U", "-w", "-")
	} else {
		tcpdumpCmd = append(tcpdumpCmd, "-l", "-n")
	}
	tcpdumpCmd = append(tcpdumpCmd, tcpdumpFilters...)

	var activePodName, activeContainerName string
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Strategy Selection
	if *debugFlag {
		activeContainerName = "sniffer"
		activePodName = createDebugPod(ctx, clientset, namespace, targetPod, tcpdumpCmd)
		go func() {
			<-sigChan
			fmt.Fprintf(os.Stderr, "\n[Stop] Cleaning up Standalone Pod...\n")
			grace := int64(0)
			clientset.CoreV1().Pods(namespace).Delete(context.Background(), activePodName, metav1.DeleteOptions{GracePeriodSeconds: &grace})
			os.Exit(0)
		}()
	} else {
		activePodName = targetPod.Name
		activeContainerName = injectEphemeral(ctx, clientset, namespace, targetPod, tcpdumpCmd)
		go func() { <-sigChan; cancel(); os.Exit(0) }()
	}

	streamPackets(ctx, clientset, config, namespace, activePodName, activeContainerName)
}

func injectEphemeral(ctx context.Context, clientset *kubernetes.Clientset, ns string, target *corev1.Pod, cmd []string) string {
	h := sha1.New()
	io.WriteString(h, strings.Join(cmd, ""))
	io.WriteString(h, fmt.Sprintf("%d", time.Now().UnixNano())) 
	cName := fmt.Sprintf("pd-%x", h.Sum(nil))[:12]

	fmt.Fprintf(os.Stderr, "💉 Mode: Ephemeral Container [%s]\n", cName)
	
	ephemeral := corev1.EphemeralContainer{
		EphemeralContainerCommon: corev1.EphemeralContainerCommon{
			Name:    cName,
			Image:   "ghcr.io/fnzv/podump",
			Command: cmd,
			ImagePullPolicy: corev1.PullAlways,
			SecurityContext: &corev1.SecurityContext{
				Privileged: boolPtr(true),
				Capabilities: &corev1.Capabilities{
					Add: []corev1.Capability{"NET_ADMIN", "NET_RAW"},
				},
			},
		},
	}

	// Re-fetch pod to get the latest ResourceVersion to avoid conflict errors
	latestPod, _ := clientset.CoreV1().Pods(ns).Get(ctx, target.Name, metav1.GetOptions{})
	latestPod.Spec.EphemeralContainers = append(latestPod.Spec.EphemeralContainers, ephemeral)
	
	_, err := clientset.CoreV1().Pods(ns).UpdateEphemeralContainers(ctx, latestPod.Name, latestPod, metav1.UpdateOptions{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ K8s Error: %v\n", err)
		fmt.Fprintf(os.Stderr, "💡 Try running with -debug\n")
		os.Exit(1)
	}
	return cName
}

func createDebugPod(ctx context.Context, clientset *kubernetes.Clientset, ns string, target *corev1.Pod, cmd []string) string {
	pName := fmt.Sprintf("podump-dbg-%x", sha1.Sum([]byte(fmt.Sprintf("%s%d", target.Name, time.Now().UnixNano()))))[:18]
	fmt.Fprintf(os.Stderr, "🚀 Mode: Standalone Pod [%s] on node %s\n", pName, target.Spec.NodeName)

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: pName, 
			Namespace: ns,
		},
		Spec: corev1.PodSpec{
			NodeName: target.Spec.NodeName,
			Containers: []corev1.Container{{
				Name:    "sniffer",
				Image:   "ghcr.io/fnzv/podump",
				Command: cmd,
				SecurityContext: &corev1.SecurityContext{Privileged: boolPtr(true)},
			}},
			HostNetwork: true,
			RestartPolicy: corev1.RestartPolicyNever,
		},
	}
	_, err := clientset.CoreV1().Pods(ns).Create(ctx, pod, metav1.CreateOptions{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Pod Creation Error: %v\n", err)
		os.Exit(1)
	}
	return pName
}

func streamPackets(ctx context.Context, clientset *kubernetes.Clientset, config *rest.Config, ns, pod, container string) {
	fmt.Fprintf(os.Stderr, "⏳ Waiting for container to be ready...\n")
	for {
		p, err := clientset.CoreV1().Pods(ns).Get(ctx, pod, metav1.GetOptions{})
		if err != nil {
			time.Sleep(1 * time.Second)
			continue
		}
		
		// Search for the specific container name in statuses
		found := false
		allStatuses := append(p.Status.ContainerStatuses, p.Status.EphemeralContainerStatuses...)
		for _, s := range allStatuses {
			if s.Name == container {
				if s.State.Running != nil {
					found = true
					break
				}
				if s.State.Terminated != nil {
					fmt.Fprintf(os.Stderr, "❌ Container terminated with exit code %d\n", s.State.Terminated.ExitCode)
					os.Exit(1)
				}
			}
		}

		if found { break }
		time.Sleep(1 * time.Second)
	}

	fmt.Fprintf(os.Stderr, "🚀 Capture Active!\n")
	req := clientset.CoreV1().RESTClient().Post().Resource("pods").Namespace(ns).Name(pod).SubResource("attach").
		VersionedParams(&corev1.PodAttachOptions{Container: container, Stdout: true, Stderr: true}, scheme.ParameterCodec)

	exec, _ := remotecommand.NewSPDYExecutor(config, "POST", req.URL())
	_ = exec.Stream(remotecommand.StreamOptions{Stdout: os.Stdout, Stderr: os.Stderr})
}