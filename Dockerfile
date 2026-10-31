# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e

# Pin the multi-platform toolchain manifest verified by Dependabot
FROM golang:1.27.3-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS builder

WORKDIR /src

# Cache dependencies before copying source
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# Copy the application package and its embedded assets
COPY cmd/ghoney ./cmd/ghoney
ARG VERSION=v0.1.5
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w -X main.buildVersion=${VERSION}" \
    -o /out/ghoney \
    ./cmd/ghoney

# Pin the multi-platform runtime manifest verified by Dependabot
FROM gcr.io/distroless/static-debian13:nonroot@sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99

COPY --from=builder --chown=nonroot:nonroot /out/ghoney /ghoney

# Bind the admin listener to the container interface for port publishing
ENV GHONEY_ADMIN_ADDR=:9090

EXPOSE 8080 9090

ENTRYPOINT ["/ghoney"]
