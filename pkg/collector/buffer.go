package collector

import (
	"sync"
	"sync/atomic"

	"github.com/executeid/ztre/pkg/observability"
	"go.uber.org/zap"
)

// EventBuffer provides a high-throughput, bounded, non-blocking in-memory queue.
type EventBuffer struct {
	events      chan *SecurityEvent
	capacity    int
	dropped     uint64
	logger      *zap.Logger
	closeOnce   sync.Once
	isClosed    atomic.Bool
}

// NewEventBuffer creates an event queue with the specified capacity.
func NewEventBuffer(capacity int, logger *zap.Logger) *EventBuffer {
	if capacity <= 0 {
		capacity = 50000
	}

	return &EventBuffer{
		events:   make(chan *SecurityEvent, capacity),
		capacity: capacity,
		logger:   logger,
	}
}

// Push adds an event to the buffer. If the buffer is full, it drops the event
// and increments the dropped counter to prevent memory exhaustion (overflow strategy).
func (b *EventBuffer) Push(event *SecurityEvent) bool {
	if b.isClosed.Load() || event == nil {
		return false
	}

	select {
	case b.events <- event:
		observability.EventsIngestedTotal.WithLabelValues(string(event.EventType), event.Namespace).Inc()
		return true
	default:
		// Queue is full: drop and record metric
		d := atomic.AddUint64(&b.dropped, 1)
		observability.EventsDroppedTotal.Inc()

		// Log periodically (every 100 drops) to avoid log spamming
		if d%100 == 1 {
			b.logger.Warn("event buffer full, dropping events",
				zap.Uint64("total_dropped", d),
				zap.Int("capacity", b.capacity),
				zap.String("sample_pod", event.PodName),
			)
		}
		return false
	}
}

// Events returns the read-only channel for consumer worker goroutines.
func (b *EventBuffer) Events() <-chan *SecurityEvent {
	return b.events
}

// DroppedCount returns the total number of dropped events.
func (b *EventBuffer) DroppedCount() uint64 {
	return atomic.LoadUint64(&b.dropped)
}

// Len returns the current number of events queued in the buffer.
func (b *EventBuffer) Len() int {
	return len(b.events)
}

// Cap returns the maximum capacity of the buffer.
func (b *EventBuffer) Cap() int {
	return b.capacity
}

// Close gracefully closes the event channel.
func (b *EventBuffer) Close() {
	b.closeOnce.Do(func() {
		b.isClosed.Store(true)
		close(b.events)
	})
}
