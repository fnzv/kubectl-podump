# Podump 🐳📦  
*A zero-downtime Kubernetes network sniffer*

Podump is a lightweight Kubernetes CLI tool that lets you capture and **analyze live network traffic from one or multiple Pods** without restarting them. It leverages **Ephemeral Containers** (or optional debug Pods) to inject a `tcpdump` sniffer directly into a Pod’s network namespace at runtime.

Beyond raw packet capture, Podump now provides **real-time traffic statistics, protocol breakdowns, and optional HTTP request insights**, making it a powerful observability toool for live clusters.

---

## 💔 Features

- **Zero Downtime**
  Capture traffic without modifying deployments or restarting Pods.

- **Multi-Pod Sniffing**
  Capture traffic from multiple Pods simultaneously with color-coded output.

- **Ephemeral Containers by Default**
  Injects a privileged sniffer container on the fly using the EphemeralContainers API.

- **Debug Pod Mode**
  Supports applications using `hostNetwork: true` via a standalone debug Pod (`-debug`).

- **Auto Discovery**
  Find Pods by partial name or by Kubernetes label selector.

- **PCAP Support**
  Stream raw PCAP data directly to Wireshark or write per-Pod capture files.

- **Live Traffic Statistics**
  Automatic summary on exit:
  - Total traffic per Pod
  - TCP / UDP / ICMP breakdown
  - Top remote IP “talkers”

- **HTTP Request Parsing (Optional)**
  Detect and summarize top HTTP points (`http` flag).

- **Context Aware**
  Automatically detects the active namespace from your kubeconfig.

- **DNS Awareness**
  Resolves Pod IPs and Services automatically, with optional reverse DNS lookup control.

- **Non-Intrusive & Collision-Safe**
  Unique container and Pod names prevent conflicts.

---

## 🚀 Installation

### Using Krew
```
$ kubectl krew install podump
Updated the local copy of plugin index.
Installing plugin: podump
Installed plugin: podump
\
 | Use this plugin:
 | 	kubectl podump
 | Documentation:
 | 	https://github.com/fnzv/kubectl-podump
 | Caveats:
 | \
 |  | Usage:
 |  |   kubectl podump [pod-name]
 |  | Examples:
 |  |   kubectl podump -n monitoring prometheus port 9090
 |  |   kubectl podump my-app --pcap > capture.pcap
 | /
/
WARNING: You installed plugin "podump" from the krew-index plugin repository.
   These plugins are not audited for security by the Krew maintainers.
   Run them at your own risk.
```

### Using Go
```bash
go install github.com/fnzv/podump@latest
```

### Using the Container Image
```bash
docker pull ghcr.io/fnzv/podump:latest
```

---

## 📛 Usage

```bash
podump [options] [pod-name-search] [tcpdump-filters]
```


```
kubectl podump example-monitoring-agent-abc12345-xyz89
📡 Sniffing 1 pod(s)...

[example-monitoring-agent-abc12345-xyz89] 12:34:56.123456 eth0  In  IP 192.0.2.10.54321 > 10.0.0.20.9000: Flags [P.], seq 1111111111:1111111400, ack 2222222222, win 512, options [nop,nop,TS val 123456789 ecr 987654321], length 289
[example-monitoring-agent-abc12345-xyz89] 12:34:56.124001 eth0  Out IP 10.0.0.20.40000 > 198.51.100.53.53: 1234+ A? api.example.internal. (45)
[example-monitoring-agent-abc12345-xyz89] 12:34:56.124300 eth0  In  IP 198.51.100.53.53 > 10.0.0.20.40000: 1234* 1/0/0 A 203.0.113.42 (78)
[example-monitoring-agent-abc12345-xyz89] 12:34:56.125800 eth0  Out IP 10.0.0.20.40100 > 198.51.100.53.53: 5678+ AAAA? api.example.internal. (45)
[example-monitoring-agent-abc12345-xyz89] 12:34:56.128900 eth0  In  IP 198.51.100.53.53 > 10.0.0.20.40100: 5678 1/0/0 AAAA 1001:db8::42 (96)
[example-monitoring-agent-abc12345-xyz89] 12:34:56.130400 eth0  Out IP 10.0.0.20 > 203.0.113.42: ICMP echo request, id 4242, seq 10101, length 32
[example-monitoring-agent-abc12345-xyz89] 12:34:56.131900 eth0  Out IP 10.0.0.20.9000 > 192.0.2.10.54321: Flags [.], ack 289, win 8192, options [nop,nop,TS val 987654999 ecr 123456789], length 0

^C
📊 --- TRAFFIC SUMMARY (4s) ---

📦 POD: example-monitoring-agent-abc12345-xyz89 (Total: 0.88 KB)
   ├─ TCP: 0.3 KB | UDP: 0.0 KB | ICMP: 0.1 KB
   └─ TOP TALKERS:
      • 10.0.0.20        (pod/example-monitoring-agent-abc12345-xyz89)      0.4 KB
      • 198.51.100.53   (unknown)                                           0.2 KB
      • 192.0.2.10      (pod/example-metrics-backend-0)                    0.2 KB
      • 203.0.113.99    (unknown)                                           0.1 KB

------------------------------------------
---

```
## 📍 Examples
```bash
# Stream live network traffic from a single pod whose name matches "my-api-pod"
podump my-api-pod

# Stream live traffic but only show packets matching the tcpdump filter (port 80)
podump my-api-pod port 80

# Capture traffic from the pod and output raw PCAP data to stdout,
# which is redirected into a file usable by Wireshark
podump -pcap my-api-pod > capture.pcap

# Capture traffic from all pods matching "api" and save each pod’s traffic
# into a separate PCAP file under a timestamped directory
podump -pcap api

# Capture traffic from all pods matching the Kubernetes label selector
# (no pod name argument is required when using -l)
podump -l app=nginx

# Enable HTTP request parsing and statistics (GET/POST/etc + paths),
# useful for debugging API behavior (more CPU-intensive)
podump -http api

# Disable reverse DNS lookups for remote IPs to avoid delays or noise
# (only raw IP addresses will be shown)
podump -nodns api

# Run Podump in the "production" namespace instead of the current context
podump -n production auth-service

# Use a standalone privileged debug pod instead of ephemeral containers,
# required for workloads running with hostNetwork: true
podump -debug sensitive-app
```

---

## 📖 How It Works

Podump uses as default the Kubernetes EphemeralContainers API. (eventhough it supports debug containers)
Unlike standard sidecars, these are created at runtime. 

Search: It finds the target Pod using your search term. 

Inject: It creates a privileged ephemeral container using the ghcr.io/fnzv/podump image. 

Attach: It attaches to the container's stdout to stream the tcpdump output back to your terminal.

---

## 💙 Security & Requirements

Permissions: You must have permissions to update the pods/ephemeralcontainers subresource in your cluster. 
Cluster Version: Requires Kubernetes v1.23+ (when Ephemeral Containers became stable).


---

## 📄 License

MIT License.
