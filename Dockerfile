# syntax=docker/dockerfile:1

# Build with the Go version declared by the module
ARG GO_VERSION=1.26.5
FROM golang:${GO_VERSION}-alpine AS builder

WORKDIR /src

# Cache dependencies before copying source
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# Embed static assets in the binary
COPY main.go ./
COPY static ./static
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /out/ghoney \
    .

# Ship only the static binary
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder --chown=nonroot:nonroot /out/ghoney /ghoney

# Bind the admin listener to the container interface for port publishing
ENV GHONEY_ADMIN_ADDR=:9090

EXPOSE 8080 9090

ENTRYPOINT ["/ghoney"]
