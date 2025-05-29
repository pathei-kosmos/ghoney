# Stage 1: Build the Go application
ARG GO_VERSION=1.24.3
FROM golang:${GO_VERSION}-alpine AS builder

WORKDIR /app

# Copy go.mod and go.sum files to leverage Docker cache
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# Copy the rest of the application source code
COPY . .

# Build the Go application as a static binary
# -ldflags="-w -s" strips debug information and symbol table, reducing binary size
# CGO_ENABLED=0 ensures a static binary without C dependencies
RUN CGO_ENABLED=0 GOOS=linux go build -v -a -installsuffix cgo -ldflags="-w -s" -o /ghoney-server main.go

# Stage 2: Create the final minimal image
FROM gcr.io/distroless/base-debian12 AS final

# Set a non-root user
USER nonroot:nonroot

WORKDIR /app

# Copy the static binary from the builder stage
COPY --from=builder /ghoney-server /ghoney-server

# Copy static assets for the dashboard
COPY static ./static

# Expose the port the app runs on (honeypot and dashboard share this port inside container)
EXPOSE 8080

# Command to run the application
CMD ["/ghoney-server"]