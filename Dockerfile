# syntax=docker/dockerfile:1@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32

# Pin the multi-platform toolchain manifest verified by Dependabot
FROM golang:1.26.8-alpine@sha256:ce864e7223ac17b1775e6fd0b4c0db580c2eb50e7953a427916379e4b92a1628 AS builder

WORKDIR /src

# Cache dependencies before copying source
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# Copy the application package and its embedded assets
COPY cmd/ghoney ./cmd/ghoney
ARG VERSION=v0.1.4
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w -X main.buildVersion=${VERSION}" \
    -o /out/ghoney \
    ./cmd/ghoney

# Pin the multi-platform runtime manifest verified by Dependabot
FROM gcr.io/distroless/static-debian13:nonroot@sha256:1c2c046bc09ed40fad370b599a0b1ae7987f55b01e247cf27a7c27cd97e5bbc7

COPY --from=builder --chown=nonroot:nonroot /out/ghoney /ghoney

# Bind the admin listener to the container interface for port publishing
ENV GHONEY_ADMIN_ADDR=:9090

EXPOSE 8080 9090

ENTRYPOINT ["/ghoney"]
