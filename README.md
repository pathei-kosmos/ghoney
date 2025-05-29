# 🍯 ghoney - a minimalist HTTP canary honeypot server
```
       _                            
  __ _| |__   ___  _ __   ___ _   _ 
 / _` | '_ \ / _ \| '_ \ / _ \ | | |
| (_| | | | | (_) | | | |  __/ |_| |
 \__, |_| |_|\___/|_| |_|\___|\__, |
 |___/                        |___/ 
```

[![Go Version](https://img.shields.io/badge/Go-1.24.3-blue.svg)](https://golang.org/dl/)
[![Docker](https://img.shields.io/badge/Docker-Distroless_gVisor_Seccomp-blue.svg)](https://www.docker.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen)](#)

`ghoney` is an intentionally vulnerable, minimalist HTTP server designed as a canary honeypot. It's built in [Go](https://go.dev/) (< 500 LOC for the server itself), packaged in a hardened Docker container ([Distroless](https://github.com/GoogleContainerTools/distroless), [gVisor](https://gvisor.dev/), [Seccomp](https://en.wikipedia.org/wiki/Seccomp)), designed to collect [Prometheus-compatible](https://prometheus.io/) metrics, and features a simple real-time dashboard.

---

## 🚀 Quickstart

1.  **Prerequisites**:
    *   Git
    *   Docker Engine
    *   **gVisor (`runsc`) installed and configured as a Docker runtime**
        *   Follow [gVisor's installation guide](https://gvisor.dev/docs/user_guide/install/#install-latest)

2.  **Clone the Repository**:
    ```bash
    git clone https://github.com/pathei-kosmos/ghoney
    cd ghoney
    ```

3.  **Build the Docker Image**:
    ```bash
    docker build -t ghoney:latest --build-arg GO_VERSION=1.24.3 .
    ```

4.  **Run the `ghoney` Container**:
    ```bash
    docker run -d \
      --name ghoney_server \
      --runtime=runsc \
      --security-opt seccomp=$(pwd)/seccomp.json \
      --security-opt no-new-privileges \
      -p 80:8080 \
      --restart unless-stopped \
      --read-only \
      --tmpfs /tmp \
      --tmpfs /run \
      --log-driver=json-file \
      --log-opt max-size=10m \
      --log-opt max-file=3 \
      ghoney:latest
    ```

5.  **Access `ghoney`**:
    *   **Honeypot Endpoints**: `http://localhost:80` (`/admin`, `/api/v1/auth`, `/.git/config`)
    *   **Dashboard**: `http://localhost:80/dashboard`
    *   **Prometheus Metrics**: `http://localhost:80/metrics`
    *   **Health Check**: `http://localhost:80/health`

6.  **View Logs**:
    ```bash
    docker logs -f ghoney_server
    ```

## 🏗️ Architecture

`ghoney` operates within a securely sandboxed Docker environment:

```mermaid
graph TD
    A[Attacker/Scanner] -->|HTTP Request| B(Host Ports 80);
    B --> C{Docker Engine};
    C -->|Runtime: runsc| D[gVisor Sandbox];
    D --> E[ghoney Go App Container];
    E -->|Endpoints: /admin, /api/v1/auth, /.git/config| F[Honeypot Logic & Detection];
    E -->|UI: /dashboard, /api/dashboard-data| G[Dashboard UI & API];
    E -->|Data: /metrics| H[Prometheus Metrics];
    F -->|logfmt to stdout| I[Container Logs];
```

*   **Client**: An attacker or automated scanner interacts with exposed ports.
*   **Docker Host**: Receives requests on mapped ports.
*   **Docker Engine**: Manages the container lifecycle.
*   **gVisor (`runsc`)**: Intercepts system calls from the `ghoney` application, providing a sandboxed environment by acting as a guest kernel.
*   **Go App Container**: Runs the `ghoney` server from a distroless image with a Seccomp profile.
    *   **Honeypot Endpoints**: Serve fake content and log interactions.
    *   **Dashboard**: Serves a web UI to visualize activity.
    *   **Metrics**: Exposes Prometheus-compatible metrics.
*   **Logging**: All interactions and detected events are logged to `stdout` in `logfmt` format, managed by Docker's logging driver.

## 🍯 Honeypot

`ghoney` implements several features:

*   **`GET /admin`**:
    *   Serves a fake administrator login HTML page (`static/admin_login.html`).
*   **`POST /api/v1/auth`**:
    *   Simulates an API authentication endpoint. Always returns `HTTP 200 OK` with a static, clearly fake (expired) JWT in the response body. This might trick poorly written scanners into believing they've authenticated.
*   **`GET /.git/config`**:
    *   Mimics a publicly exposed Git configuration file. Returns plausible-looking fake `.git/config` content, including fake internal Git repository URLs and commented-out "sensitive" data like a fake CI token or credentials in a URL.

*   **Attack Detection**:
    *   Basic pattern matching for SQL injection (`' OR '1'='1`), path traversal (`../`), and common XML bomb indicators (`<!ENTITY` in payload snippets).
    *   Detection occurs on query parameters and (limited-size) request bodies.
*   **Random Delays**:
    *   Non-honeypot, undefined paths return HTTP 404 with a random delay of 1-3 seconds to mimic a real, possibly struggling, server and to slow down aggressive scanners.
*   **Tracking Cookie**:
    *   Sets a fake tracking cookie (`X-Ghoney-Trap: 1`) on the first visit to any endpoint, potentially useful for identifying returning visitors.

## 📊 Dashboard

The dashboard provides a real-time view of activity targeting the honeypot.

<p align="center">
  <img src="./img/dashboard.png" alt="Dashboard excerpt" />
</p>

**Indicators:**
*   **Recent Activity Table**: Timestamp, IP, User-Agent, Path, Attack Type, Details.
*   **Top Attacking IPs Table**: Lists IPs with the highest number of logged events.
*   **Top User Agents Table**: Lists most frequent User-Agents.
*   **Common Payload Keywords List**: Shows frequently detected keywords.
*   **Attacker Origins sList**: Lists top IPs with counts as a placeholder for a map.

## 🛡️ Security

*   **gVisor (`runsc`)**: The primary defense. gVisor intercepts syscalls from the application and executes them through its own user-space kernel, significantly limiting direct interaction with the host kernel. This provides strong sandboxing.
*   **Seccomp BPF**: A `seccomp.json` profile further restricts the set of syscalls the `runsc` sandbox process itself can make to the host kernel, adhering to the principle of least privilege.
*   **Distroless Docker Image**: The final image (`gcr.io/distroless/base-debian12`) contains only the Go application, its static assets, and essential runtime libraries. It lacks a shell, package manager, and other common utilities, drastically reducing the attack surface.
*   **Non-Root Container User**: The application runs as a `nonroot` user inside the container.
*   **Input Sanitization**:
    *   Data logged to `stdout` is sanitized to prevent log injection (newline, quote replacement).
    *   Data displayed on the dashboard (fetched from `/api/dashboard-data`) is escaped before rendering to prevent XSS.
*   **Request Limiting & Timeouts**:
    *   **Request Body Size**: Limited to 4KB. Larger requests are rejected.
    *   **Request Timeout**: Each HTTP request is limited to a 5-second processing time.
    *   **Server Timeouts**: `ReadHeaderTimeout`, `ReadTimeout`, `WriteTimeout`, `IdleTimeout` are configured on the HTTP server for robustness.
*   **Minimalist Codebase**: The Go server (`main.go`) is under 500 LOC, reducing complexity and potential for vulnerabilities.
*   **No Persistent Storage**: The honeypot is ephemeral. Logs go to `stdout` (handled by Docker) and recent events for the dashboard are stored in-memory (bounded).

---

## 🧹 Clean-up

1.  Stop the container:
    ```bash
    docker stop ghoney_server
    ```
2.  Remove the container:
    ```bash
    docker rm ghoney_server
    ```

To remove the Docker image:
```bash
docker rmi ghoney:latest
```