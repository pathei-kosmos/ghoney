# 🍯 ghoney

```text
       _
  __ _| |__   ___  _ __   ___ _   _
 / _` | '_ \ / _ \| '_ \ / _ \ | | |
| (_| | | | | (_) | | | |  __/ |_| |
 \__, |_| |_|\___/|_| |_|\___|\__, |
 |___/                        |___/
```

**A small HTTP honeypot for the noisy parts of the internet.**

<p>
  <a href="https://go.dev/"><img src="https://img.shields.io/badge/Go-1.25%2B-00ADD8?logo=go&logoColor=white" alt="Go 1.25 or newer"></a>
  <a href="https://www.docker.com/"><img src="https://img.shields.io/badge/Docker-ready-2496ED?logo=docker&logoColor=white" alt="Docker ready"></a>
  <a href="https://github.com/pathei-kosmos/ghoney/actions/workflows/ci.yml"><img src="https://github.com/pathei-kosmos/ghoney/actions/workflows/ci.yml/badge.svg" alt="CI status"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-black.svg" alt="MIT License"></a>
</p>

**ghoney** is a lightweight HTTP honeypot that exposes believable bait endpoints, detects common attack patterns, and turns the resulting traffic into structured logs, [Prometheus](https://prometheus.io/) metrics, and a local dashboard. It stays deliberately small and ephemeral, with a [Distroless](https://github.com/GoogleContainerTools/distroless) image, a non-root runtime, a read-only filesystem, and optional [gVisor](https://gvisor.dev/) and custom [Seccomp](https://en.wikipedia.org/wiki/Seccomp) isolation.

![ghoney dashboard](img/dashboard.png)

## ✨ What it catches

- SQL injection, path traversal, command injection, SSRF, LFI/RFI, and XML entity attacks
- XSS, JNDI/Log4Shell, and NoSQL injection
- Percent-encoded and obfuscated payloads across URLs, request bodies, and selected headers
- Gzip request bodies and Base64 values in query, form, and JSON fields
- Requests to decoy routes such as `/admin`, `/api/v1/auth`, and `/.git/config`

Detections have `high` or `medium` confidence. Strong signals are logged at `warn`, while ambiguous ones stay at `info`. A request produces at most one event per attack family.

Request bodies are limited to 4 KiB before and after gzip decompression, with `413` returned above either limit. Metric labels and concurrency are also bounded. The memory buffer holds at most 100 events and preserves stronger signals when it fills up.

The Git lure uses a random fake token under the reserved `.example.com` namespace, so it never points at a real external service. CMS routes and scanner fingerprinting remain outside the scope of this small honeypot.

## 🚀 Quick start

You need Git and a running Docker Engine. Replace the example admin password before starting the container.

```bash
git clone https://github.com/pathei-kosmos/ghoney.git
cd ghoney
docker build -t ghoney .
docker run -d --name ghoney_server --env GHONEY_ADMIN_PASSWORD='USE-AT-LEAST-16-CHARS' --cap-drop=ALL --security-opt no-new-privileges -p 8080:8080 -p 127.0.0.1:9090:9090 --restart unless-stopped --read-only --memory=128m --cpus=1 --pids-limit=64 --log-driver=json-file --log-opt max-size=10m --log-opt max-file=3 ghoney
```

Open the local dashboard at [localhost:9090/dashboard](http://localhost:9090/dashboard) and sign in as `ghoney` with that password.

| URL | Purpose |
| --- | --- |
| `localhost:8080/admin` | Decoy administrator login |
| `localhost:8080/api/v1/auth` | Decoy authentication API |
| `localhost:8080/.git/config` | Decoy exposed repository configuration |
| `localhost:9090/dashboard` | Local activity dashboard |
| `localhost:9090/metrics` | Bounded Prometheus metrics |
| `localhost:9090/health` | Health check |

Port `8080` is the public honeypot surface. Port `9090` is published on host loopback only, so remote hosts cannot reach the dashboard directly.

The public and administrative listeners accept these environment variables:

| Variable | Default | Rule |
| --- | --- | --- |
| `GHONEY_ADDR` | `:8080` | Public listen address |
| `GHONEY_ADMIN_ADDR` | `127.0.0.1:9090` | Docker defaults to `:9090`, non-loopback addresses require authentication |
| `GHONEY_ADMIN_USER` | `ghoney` | Must not contain `:` or control characters |
| `GHONEY_ADMIN_PASSWORD` | unset | Use at least 16 characters, with a 256-byte limit |
| `GHONEY_ADMIN_PASSWORD_FILE` | unset | Reads the password from a file and cannot be combined with `GHONEY_ADMIN_PASSWORD` |

Authentication protects `/dashboard`, its assets, `/api/dashboard-data`, and `/metrics`. `/health` stays public for probes. **Basic Auth controls access but does not encrypt traffic. Keep the admin port on host loopback or place every network connection behind HTTPS, an SSH tunnel, or another trusted encrypted transport.**

## 🧪 Verify detection

Together, these requests generate at least one event for every supported attack family:

```bash
curl -X POST "http://localhost:8080/api/v1/auth" -H "Content-Type: application/x-www-form-urlencoded" --data "u=' OR 1=1 --"
curl "http://localhost:8080/?p=..%2F..%2Fetc%2Fpasswd"
curl -X POST "http://localhost:8080/" -H "Content-Type: application/xml" --data '<!ENTITY x SYSTEM "file:///etc/passwd">'
curl "http://localhost:8080/?cmd=whoami%20%26%26%20id"
curl "http://localhost:8080/?url=http://169.254.169.254/latest/meta-data/"
curl "http://localhost:8080/?file=php://filter/read=convert.base64-encode/resource=/etc/passwd"
curl "http://localhost:8080/?q=%3Csvg%20onload%3Dalert(1)%3E"
curl -H 'User-Agent: ${jndi:ldap://127.0.0.1/a}' "http://localhost:8080/"
curl "http://localhost:8080/?user%5B%24ne%5D=guest"
```

The authentication endpoint always returns `HTTP 401` JSON with `Cache-Control: no-store`. It never emits a JWT, but its payload is still inspected. Unknown routes return `HTTP 404` without delay and appear as weak access events in the dashboard.

Review the events in the dashboard or from the command line:

```bash
curl --user ghoney http://localhost:9090/api/dashboard-data
docker logs ghoney_server
```

`ghoney_honeypot_attacks_total` keeps its original labels. `ghoney_honeypot_detections_total` adds the bounded `confidence` label. Prometheus can authenticate directly:

```yaml
scrape_configs:
  - job_name: ghoney
    static_configs:
      - targets: ["ghoney:9090"]
    basic_auth:
      username: ghoney
      password_file: /run/secrets/ghoney_admin_password
```

For Docker or Kubernetes secrets, mount the same secret file into ghoney and set `GHONEY_ADMIN_PASSWORD_FILE` to its container path. The direct environment variable remains available for simple local runs.

The event buffer and local counters reset on restart. Use Docker logs and Prometheus for retention.

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

The quick start uses Docker's default Seccomp policy automatically. It does not require the custom profile or gVisor and works with Docker Engine on Linux or Docker Desktop running Linux containers on Windows or macOS.

### Custom Seccomp profile

On x86-64 Linux, you can replace Docker's default policy with ghoney's [project-specific Seccomp allowlist](seccomp.json) for tighter syscall isolation. Run the following command from the repository root and replace the example admin password before starting the container:

```bash
docker run -d --name ghoney_server \
  --env GHONEY_ADMIN_PASSWORD='USE-AT-LEAST-16-CHARS' \
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

The custom profile keeps `execve` because the container runtime needs it to start `/ghoney`, the application itself never launches child processes.

### Add gVisor

For an additional isolation layer, install `runsc` and confirm that the `runsc` runtime appears in `docker info`. You can then combine gVisor with the custom Seccomp profile by adding `--runtime=runsc` to the command above. gVisor is not generally available through Docker Desktop on Windows or macOS.

> **ghoney** is designed to receive hostile input. Expose only port `8080`, never place real credentials in a decoy, and put remote dashboard access behind an authenticated HTTPS proxy or SSH tunnel.

## 🧹 Cleanup

```bash
docker stop ghoney_server
docker rm ghoney_server
docker image rm ghoney
```

Released under the [MIT License](LICENSE).
