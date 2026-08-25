# syntax=docker/dockerfile:1

# Build with the toolchain checked in CI
ARG GO_VERSION=1.26.7
FROM golang:${GO_VERSION}-alpine AS builder

WORKDIR /src

# Cache dependencies before copying source
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# Copy production sources without the tests
COPY main.go bootstrap.go detection.go server.go telemetry.go ./
COPY static ./static
ARG VERSION=v0.1.2
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w -X main.buildVersion=${VERSION}" \
    -o /out/ghoney \
    .

# Ship only the static binary
FROM gcr.io/distroless/static-debian13:nonroot

COPY --from=builder --chown=nonroot:nonroot /out/ghoney /ghoney

# Bind the admin listener to the container interface for port publishing
ENV GHONEY_ADMIN_ADDR=:9090

EXPOSE 8080 9090

ENTRYPOINT ["/ghoney"]
