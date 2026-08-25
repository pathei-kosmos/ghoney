package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
	"unicode"
)

// Read an environment override and ignore blank values
func envOrDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

// Read the admin secret from one source without loading unbounded files
func loadAdminPassword() (string, error) {
	password := os.Getenv(envAdminPassword)
	passwordFile := os.Getenv(envAdminPasswordFile)
	if password != "" && passwordFile != "" {
		return "", fmt.Errorf("%s and %s cannot be used together", envAdminPassword, envAdminPasswordFile)
	}
	if passwordFile == "" {
		return password, nil
	}

	file, err := os.Open(passwordFile)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", envAdminPasswordFile, err)
	}
	contents, readErr := io.ReadAll(io.LimitReader(file, int64(maxAdminPasswordBytes+3)))
	closeErr := file.Close()
	if readErr != nil {
		return "", fmt.Errorf("read %s: %w", envAdminPasswordFile, readErr)
	}
	if closeErr != nil {
		return "", fmt.Errorf("close %s: %w", envAdminPasswordFile, closeErr)
	}

	password = string(contents)
	if strings.HasSuffix(password, "\r\n") {
		password = strings.TrimSuffix(password, "\r\n")
	} else if strings.HasSuffix(password, "\n") {
		password = strings.TrimSuffix(password, "\n")
	}
	return password, nil
}

// Validate security settings before opening sockets
func loadConfig() (appConfig, error) {
	configuration := appConfig{
		publicAddr: envOrDefault(envPublicAddr, defaultPublicAddr),
		adminAddr:  envOrDefault(envAdminAddr, defaultAdminAddr),
	}
	username := envOrDefault(envAdminUser, defaultAdminUser)
	for _, character := range username {
		if character == ':' || unicode.IsControl(character) {
			return appConfig{}, fmt.Errorf("%s contains a forbidden character", envAdminUser)
		}
	}
	password, err := loadAdminPassword()
	if err != nil {
		return appConfig{}, err
	}
	if password != "" && (len(password) < minAdminPasswordBytes || len(password) > maxAdminPasswordBytes) {
		return appConfig{}, fmt.Errorf("admin password must contain between %d and %d bytes", minAdminPasswordBytes, maxAdminPasswordBytes)
	}
	if !isLiteralLoopbackAddress(configuration.adminAddr) && password == "" {
		return appConfig{}, fmt.Errorf("%s or %s is required when %s is not literal loopback", envAdminPassword, envAdminPasswordFile, envAdminAddr)
	}
	if password != "" {
		configuration.adminCredential = adminCredentials{
			enabled:      true,
			usernameHash: sha256.Sum256([]byte(username)),
			passwordHash: sha256.Sum256([]byte(password)),
		}
	}
	return configuration, nil
}

// Accept only explicit loopback addresses without DNS resolution
func isLiteralLoopbackAddress(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	host = strings.TrimSpace(strings.Trim(host, "[]"))
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	if strings.Contains(host, ":") {
		return ip.Equal(net.IPv6loopback)
	}
	ipv4 := ip.To4()
	return ipv4 != nil && ipv4[0] == 127
}

// Use explicit listeners so both binds finish before startup
func defaultRuntimeDependencies() runtimeDependencies {
	return runtimeDependencies{
		listen: net.Listen,
		serve: func(server *http.Server, listener net.Listener) error {
			return server.Serve(listener)
		},
	}
}

// Open both sockets before reporting readiness
func run(ctx context.Context) error {
	configuration, err := loadConfig()
	if err != nil {
		return err
	}
	return runWithDependencies(ctx, configuration, defaultRuntimeDependencies())
}

// Clean up partial startup and collect both server errors
func runWithDependencies(ctx context.Context, configuration appConfig, dependencies runtimeDependencies) error {
	publicListener, err := dependencies.listen("tcp", configuration.publicAddr)
	if err != nil {
		return fmt.Errorf("listen on public address %q: %w", configuration.publicAddr, err)
	}
	adminListener, err := dependencies.listen("tcp", configuration.adminAddr)
	if err != nil {
		closeErr := publicListener.Close()
		return errors.Join(fmt.Errorf("listen on admin address %q: %w", configuration.adminAddr, err), closeErr)
	}

	servers := []*http.Server{
		newHTTPServer(configuration.publicAddr, publicHandler()),
		newHTTPServer(configuration.adminAddr, adminHandler(configuration.adminCredential)),
	}
	listeners := []net.Listener{publicListener, adminListener}
	serverErrors := make(chan error, len(servers))
	for index := range servers {
		server := servers[index]
		listener := listeners[index]
		go func() {
			serverErrors <- dependencies.serve(server, listener)
		}()
	}

	structuredLogger.Printf("%slevel=info ts=%s msg=%q public_addr=%q admin_addr=%q",
		asciiArtBanner,
		time.Now().UTC().Format(time.RFC3339),
		"ghoney listening",
		configuration.publicAddr,
		configuration.adminAddr,
	)

	collected := make([]error, 0, len(servers)+len(servers))
	serveResults := 0
	select {
	case <-ctx.Done():
	case serveErr := <-serverErrors:
		serveResults++
		collected = append(collected, normalizeServerError(serveErr))
	}

	// Start both graceful shutdowns under one deadline
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	shutdownErrors := make(chan error, len(servers))
	for _, server := range servers {
		server := server
		go func() {
			shutdownErrors <- server.Shutdown(shutdownCtx)
		}()
	}
	for range servers {
		collected = append(collected, <-shutdownErrors)
	}
	// Close both listeners in case cancellation wins before Serve starts
	for _, listener := range listeners {
		if closeErr := listener.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			collected = append(collected, closeErr)
		}
	}
	for serveResults < len(servers) {
		collected = append(collected, normalizeServerError(<-serverErrors))
		serveResults++
	}
	return errors.Join(collected...)
}

// Ignore only the normal result of graceful shutdown
func normalizeServerError(err error) error {
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	if err == nil {
		return errors.New("HTTP server stopped unexpectedly")
	}
	return err
}
