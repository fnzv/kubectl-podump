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

const version = "1.1.0"

func boolPtr(b bool) *bool { return &b }

func printBanner() {
	banner := `
  _____           _                      
 |  __ \         | |                     
 | |__) |__   __| |_   _ _ __ ___  _ __  
 |  ___/ _ \ / _` + "`" + ` | | | | '_ ` + "`" + ` _ \| '_ \ 
 | |  | (_) | (_| | |_| | | | | | | |_) |
 |_|   \___/ \__,_|\__,_|_| |_| |_| .__/ 
                                  | |    
      v%-7s                     |_|    
`
	fmt.Fprintf(os.Stderr, banner, version)
}

func main() {
	// 1. Define Flags
	nsFlag := flag.String("n", "", "Namespace (defaults to current context)")
	helpFlag := flag.Bool("h", false, "Show help")
	pcapFlag := flag.Bool("pcap", false, "Output raw PCAP binary data")

	// Custom Usage to explain positional args
	flag.Usage = func() {
		printBanner()
		fmt.Fprintf(os.Stderr, "Usage: podump [options] <pod-search-term> [tcpdump-filters]\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  podump -n monitoring prometheus port 9090\n")
		fmt.Fprintf(os.Stderr, "  podump my-app --pcap > capture.pcap\n")
		os.Exit(0)
	}

	flag.Parse()
	args := flag.Args()

	if *helpFlag || len(args) < 1 {
		flag.Usage()
	}

	searchTerm := args[0]
	tcpdumpFilters := args[1:]

	// 2. K8s Config & Namespace Logic
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, &clientcmd.ConfigOverrides{})
	
	// Use flag if provided, otherwise detect from context
	namespace := *nsFlag
	if namespace == "" {
		namespace, _, _ = kubeConfig.Namespace()
		if namespace == "" {
			namespace = "default"
		}
	}

	config, _ := kubeConfig.ClientConfig()
	clientset, _ := kubernetes.NewForConfig(config)
	ctx, cancel := context.WithCancel(context.Background())

	// 3. Signal Handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Fprintf(os.Stderr, "\n[Stop] Cleaning up...\n")
		cancel()
		os.Exit(0)
	}()

	// 4. Pod Discovery
	printBanner()
	fmt.Fprintf(os.Stderr, "🔍 Searching for '%s' in namespace '%s'...\n", searchTerm, namespace)
	pods, err := clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Error: %v\n", err)
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
		fmt.Fprintf(os.Stderr, "❌ No pod found matching '%s' in namespace '%s'\n", searchTerm, namespace)
		os.Exit(1)
	}

	// 5. Build Command
	tcpdumpCmd := []string{"tcpdump", "-i", "any", "--immediate-mode"}
	if *pcapFlag {
		tcpdumpCmd = append(tcpdumpCmd, "-U", "-w", "-")
	} else {
		tcpdumpCmd = append(tcpdumpCmd, "-l", "-n")
	}
	tcpdumpCmd = append(tcpdumpCmd, tcpdumpFilters...)

	// Hashing for immutable container safety
	h := sha1.New()
	io.WriteString(h, strings.Join(tcpdumpCmd, ""))
	containerName := fmt.Sprintf("pd-%x", h.Sum(nil))[:12]

	// 6. Injection
	exists := false
	for _, ec := range targetPod.Spec.EphemeralContainers {
		if ec.Name == containerName {
			exists = true
			break
		}
	}

	if !exists {
		fmt.Fprintf(os.Stderr, "💉 Injecting sniffer [%s] into %s...\n", containerName, targetPod.Name)
		ephemeral := corev1.EphemeralContainer{
			EphemeralContainerCommon: corev1.EphemeralContainerCommon{
				Name:    containerName,
				Image:   "ghcr.io/fnzv/podump",
				Command: tcpdumpCmd,
				SecurityContext: &corev1.SecurityContext{
					Privileged: boolPtr(true),
				},
			},
		}
		targetPod.Spec.EphemeralContainers = append(targetPod.Spec.EphemeralContainers, ephemeral)
		_, err := clientset.CoreV1().Pods(namespace).UpdateEphemeralContainers(ctx, targetPod.Name, targetPod, metav1.UpdateOptions{})
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Injection failed: %v\n", err)
			os.Exit(1)
		}
	}

	streamPackets(ctx, clientset, config, namespace, targetPod.Name, containerName)
}

func streamPackets(ctx context.Context, clientset *kubernetes.Clientset, config *rest.Config, ns, pod, container string) {
	fmt.Fprintf(os.Stderr, "⏳ Waiting for container to be ready...\n")
	for {
		p, _ := clientset.CoreV1().Pods(ns).Get(ctx, pod, metav1.GetOptions{})
		for _, s := range p.Status.EphemeralContainerStatuses {
			if s.Name == container && s.State.Running != nil {
				goto ready
			}
		}
		time.Sleep(1 * time.Second)
	}

ready:
	time.Sleep(500 * time.Millisecond)
	fmt.Fprintf(os.Stderr, "🚀 Podump Active. Capturing traffic...\n")

	req := clientset.CoreV1().RESTClient().Post().
		Resource("pods").Namespace(ns).Name(pod).
		SubResource("attach").
		VersionedParams(&corev1.PodAttachOptions{
			Container: container,
			Stdin:     true,
			Stdout:    true,
			Stderr:    true,
			TTY:       true,
		}, scheme.ParameterCodec)

	exec, _ := remotecommand.NewSPDYExecutor(config, "POST", req.URL())
	_ = exec.Stream(remotecommand.StreamOptions{
		Stdout: os.Stdout,
		Stderr: os.Stderr,
		Tty:    true,
	})
}