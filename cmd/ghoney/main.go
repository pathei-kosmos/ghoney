package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// buildVersion is replaced by release builds
var buildVersion = "dev"

// Tie server shutdown to process signals
func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err := run(ctx)
	// Limit shutdown time if stdout is blocked
	flushContext, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	stdoutEvents.shutdown(flushContext)
	cancel()
	if err != nil {
		log.Fatalf("level=fatal ts=%s msg=%q error=%q", time.Now().UTC().Format(time.RFC3339), "server stopped", err.Error())
	}
}
