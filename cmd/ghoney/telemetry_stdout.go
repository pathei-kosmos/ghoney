package main

import (
	"context"
	"log"
	"sync"
)

// Keep slow stdout writes from blocking requests
var stdoutEvents = newEventWriter(structuredLogger, 256, func(reason string) {
	stdoutEventsDroppedTotal.WithLabelValues(reason).Inc()
})

// queuedEvent holds fields already bounded by recordEvent
type queuedEvent struct {
	level string
	entry LogEntry
}

// eventWriter uses one worker and a fixed queue for stdout
type eventWriter struct {
	mu     sync.Mutex
	closed bool
	queue  chan queuedEvent
	done   chan struct{}
	onDrop func(string)
}

// Serialize writes and account for output failures without recursive logging
func newEventWriter(logger *log.Logger, capacity int, onDrop func(string)) *eventWriter {
	writer := &eventWriter{queue: make(chan queuedEvent, capacity), done: make(chan struct{}), onDrop: onDrop}
	go func() {
		defer close(writer.done)
		for event := range writer.queue {
			if err := writeStructuredEvent(logger, event.level, event.entry); err != nil {
				writer.onDrop("write_error")
			}
		}
	}()
	return writer
}

// Drop excess stdout events without blocking requests
func (writer *eventWriter) enqueue(level string, entry LogEntry) {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if writer.closed {
		writer.onDrop("shutdown")
		return
	}
	select {
	case writer.queue <- queuedEvent{level: level, entry: entry}:
	default:
		writer.onDrop("queue_full")
	}
}

// Stop accepting events and flush the queue until the deadline
func (writer *eventWriter) shutdown(ctx context.Context) {
	writer.mu.Lock()
	if !writer.closed {
		writer.closed = true
		close(writer.queue)
	}
	writer.mu.Unlock()
	select {
	case <-writer.done:
	case <-ctx.Done():
	}
}
