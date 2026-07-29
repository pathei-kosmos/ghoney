# 🍯 ghoney

```text
       _
  __ _| |__   ___  _ __   ___ _   _
 / _` | '_ \ / _ \| '_ \ / _ \ | | |
| (_| | | | | (_) | | | |  __/ |_| |
 \__, |_| |_|\___/|_| |_|\___|\__, |
 |___/                        |___/
```

**A small HTTP canary for the noisy parts of the internet.**

<p>
  <a href="https://go.dev/"><img src="https://img.shields.io/badge/Go-1.26.5-00ADD8?logo=go&logoColor=white" alt="Go 1.26.5"></a>
  <a href="https://www.docker.com/"><img src="https://img.shields.io/badge/Docker-ready-2496ED?logo=docker&logoColor=white" alt="Docker ready"></a>
  <a href="https://github.com/pathei-kosmos/ghoney/actions/workflows/ci.yml"><img src="https://github.com/pathei-kosmos/ghoney/actions/workflows/ci.yml/badge.svg" alt="CI status"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-black.svg" alt="MIT License"></a>
</p>

**ghoney** exposes believable bait endpoints, detects common attack patterns, and turns the resulting traffic into structured logs, [Prometheus](https://prometheus.io/) metrics, and a local dashboard. It stays deliberately small and ephemeral, with a [Distroless](https://github.com/GoogleContainerTools/distroless) image, a non-root runtime, a read-only filesystem, and optional [gVisor](https://gvisor.dev/) and custom [Seccomp](https://en.wikipedia.org/wiki/Seccomp) isolation.

![ghoney dashboard](img/dashboard.png)

## ✨ What it catches

- SQL injection, path traversal, command injection, SSRF, LFI/RFI, and XML entity payloads
- Requests to decoy routes such as `/admin`, `/api/v1/auth`, and `/.git/config`

Unknown routes respond with a cancellable random 1-3 second delay. Request bodies, logs, metrics labels, concurrency, and the in-memory event buffer are all bounded.

## 🚀 Quick start

You need Git and a running Docker Engine.

```bash
git clone https://github.com/pathei-kosmos/ghoney.git
cd ghoney
docker build -t ghoney .
docker run -d --name ghoney_server --cap-drop=ALL --security-opt no-new-privileges -p 8080:8080 -p 127.0.0.1:9090:9090 --restart unless-stopped --read-only --memory=128m --cpus=1 --pids-limit=64 --log-driver=json-file --log-opt max-size=10m --log-opt max-file=3 ghoney
```

Open the local dashboard at [localhost:9090/dashboard](http://localhost:9090/dashboard).

| URL | Purpose |
| --- | --- |
| `localhost:8080/admin` | Decoy administrator login |
| `localhost:8080/api/v1/auth` | Decoy authentication API |
| `localhost:8080/.git/config` | Decoy exposed repository configuration |
| `localhost:9090/dashboard` | Local activity dashboard |
| `localhost:9090/metrics` | Bounded Prometheus metrics |
| `localhost:9090/health` | Health check |

Port `8080` is the public honeypot surface. Port `9090` is published on host loopback only, so remote hosts cannot reach the dashboard directly.

## 🧪 Verify detection

These requests generate one event for each supported attack family:

```bash
curl -X POST "http://localhost:8080/api/v1/auth" -H "Content-Type: application/x-www-form-urlencoded" --data "u=' OR 1=1 --"
curl "http://localhost:8080/?p=..%2F..%2Fetc%2Fpasswd"
curl -X POST "http://localhost:8080/" -H "Content-Type: application/xml" --data '<!ENTITY x SYSTEM "file:///etc/passwd">'
curl "http://localhost:8080/?cmd=whoami%20%26%26%20id"
curl "http://localhost:8080/?url=http://169.254.169.254/latest/meta-data/"
curl "http://localhost:8080/?file=php://filter/read=convert.base64-encode/resource=/etc/passwd"
```

The authentication endpoint responds with `HTTP 200`. The other requests target the undefined `/` route and respond with `HTTP 404` after the intentional delay. All payloads are detected.

Review the events in the dashboard or from the command line:

```bash
curl http://localhost:9090/api/dashboard-data
docker logs ghoney_server
```

## 🛡️ Layered isolation

**ghoney** combines a small application surface with container-level hardening:

| Layer | Role |
| --- | --- |
| **Distroless image** | Ships the server without a shell, package manager, or unnecessary tooling |
| **Non-root + read-only** | Runs as `nonroot` with no writable application filesystem |
| **Capabilities + privileges** | Drops every Linux capability and prevents privilege escalation |
| **Resource limits** | Bounds memory, CPU, and process consumption |
| **Docker Seccomp** | Uses Docker's maintained default policy in the standard deployment |
| **Custom Seccomp** | Replaces Docker's general policy with ghoney's narrower x86-64 Linux syscall allowlist |
| **gVisor** | Optionally places a user-space kernel between ghoney and the host |

The quick start uses Docker's default Seccomp policy automatically; it does not require the custom profile or gVisor. This works with Docker Engine on Linux and Docker Desktop running Linux containers on Windows or macOS. No application data is persisted by ghoney.

For tighter syscall isolation on x86-64 Linux, ghoney includes a [project-specific Seccomp allowlist](seccomp.json) that reduces the kernel-facing attack surface beyond Docker's general-purpose default profile:

```bash
docker run -d --name ghoney_server \
  --cap-drop=ALL \
  --security-opt seccomp="$(pwd)/seccomp.json" \
  --security-opt no-new-privileges \
  -p 8080:8080 \
  -p 127.0.0.1:9090:9090 \
  --restart unless-stopped \
  --read-only \
  --memory=128m \
  --cpus=1 \
  --pids-limit=64 \
  --log-driver=json-file \
  --log-opt max-size=10m \
  --log-opt max-file=3 \
  ghoney
```

To add gVisor, install `runsc`, confirm that it appears in `docker info`, then add `--runtime=runsc` to the command above. gVisor is not generally available through Docker Desktop on Windows or macOS.

> **ghoney** is designed to receive hostile input. Expose only port `8080`, never place real credentials in a decoy, and put remote dashboard access behind an authenticated HTTPS proxy or SSH tunnel.

## 🧹 Cleanup

```bash
docker stop ghoney_server
docker rm ghoney_server
docker image rm ghoney
```

Released under the [MIT License](LICENSE).
