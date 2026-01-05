# Podump 🐳📦

Podump is a lightweight Kubernetes CLI tool that allows you to capture network traffic from any Pod without restarting it. It leverages Ephemeral Containers to inject a tcpdump sniffer into a running Pod's network namespace on the fly.
## ✨ Features

    Zero Downtime: No need to modify deployments or restart Pods.

    Auto-Discovery: Search for Pods by partial name.

    PCAP Support: Stream raw binary data directly into Wireshark or a file.

    Context Aware: Automatically detects your current namespace from kubeconfig.

    Non-Intrusive: Uses unique container naming to prevent collisions.
---

## 🚀 Installation
Using Go
```
go install github.com/fnzv/podump@latest
```

Using the Container Directly

The sniffer image is available at:
```
docker pull ghcr.io/fnzv/podump:latest
```

## 🛠 Usage

```
Usage: podump [options] <pod-search-term> [tcpdump-filters]
```
## Examples

1. Live stream traffic from a specific pod:
```
podump my-api-pod
```
2. Filter for specific traffic (e.g., Port 80):
```
podump my-api-pod port 80
```

3. Capture to a PCAP file for Wireshark:
```
podump -pcap my-api-pod > capture.pcap
```

4. Specify a namespace:
```
podump -n production auth-service
```

## 📖 How it Works

Podump uses the Kubernetes EphemeralContainers API. Unlike standard sidecars, these are created at runtime.

    Search: It finds the target Pod using your search term.

    Inject: It creates a privileged ephemeral container using the ghcr.io/fnzv/podump image.

    Attach: It attaches to the container's stdout to stream the tcpdump output back to your terminal.

## ⚙️ Options
```
Flag	Description	Default
-n	Kubernetes Namespace	Current Context
-pcap	Output raw binary PCAP data	false (text mode)
-h	Show help and examples
```
## 🛡 Security & Requirements

    Permissions: You must have permissions to update the pods/ephemeralcontainers subresource in your cluster.

    Cluster Version: Requires Kubernetes v1.23+ (when Ephemeral Containers became stable).


## 📄 License

MIT License. Feel free to use and contribute!