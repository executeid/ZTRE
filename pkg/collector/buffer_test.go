package collector

import (
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestEventBuffer_PushAndPop(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	buf := NewEventBuffer(100, logger)
	defer buf.Close()

	ev := &SecurityEvent{
		EventType: EventTypeExecve,
		Binary:    "/bin/sh",
		Namespace: "default",
		PodName:   "pod-1",
	}

	if !buf.Push(ev) {
		t.Fatal("expected push to succeed")
	}

	if buf.Len() != 1 {
		t.Fatalf("expected buffer length 1, got %d", buf.Len())
	}

	received := <-buf.Events()
	if received.Binary != "/bin/sh" {
		t.Fatalf("expected /bin/sh, got %s", received.Binary)
	}
}

func TestEventBuffer_Overflow(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	capacity := 5
	buf := NewEventBuffer(capacity, logger)
	defer buf.Close()

	// Fill buffer to max capacity
	for i := 0; i < capacity; i++ {
		ev := &SecurityEvent{EventType: EventTypeExecve, Namespace: "test", PodName: "p"}
		if !buf.Push(ev) {
			t.Fatalf("expected push %d to succeed", i)
		}
	}

	// Next push should overflow and drop gracefully
	overflowEv := &SecurityEvent{EventType: EventTypeExecve, Namespace: "test", PodName: "overflow"}
	if buf.Push(overflowEv) {
		t.Fatal("expected push to be dropped when buffer is full")
	}

	if buf.DroppedCount() != 1 {
		t.Fatalf("expected 1 dropped event, got %d", buf.DroppedCount())
	}
}

func TestEventBuffer_ConcurrentPushClose(t *testing.T) {
	logger := zap.NewNop()
	buf := NewEventBuffer(100, logger)

	var wg sync.WaitGroup
	const numProducers = 10
	ev := &SecurityEvent{EventType: EventTypeExecve, Namespace: "test", PodName: "p"}

	// Start producers pushing in loop
	for i := 0; i < numProducers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 500; j++ {
				_ = buf.Push(ev)
			}
		}()
	}

	// Drainer in background
	drainDone := make(chan struct{})
	go func() {
		defer close(drainDone)
		for range buf.Events() {
		}
	}()

	// Close buffer concurrently while producers are pushing
	time.Sleep(2 * time.Millisecond)
	buf.Close()
	// Duplicate close must be safe
	buf.Close()

	wg.Wait()
	<-drainDone
}

func BenchmarkEventBuffer_Throughput(b *testing.B) {
	logger := zap.NewNop()
	buf := NewEventBuffer(100000, logger)
	defer buf.Close()

	ev := &SecurityEvent{
		Timestamp: time.Now().UTC(),
		EventType: EventTypeExecve,
		Binary:    "/bin/bash",
		Namespace: "ztre-test",
		PodName:   "bench-pod",
	}

	var wg sync.WaitGroup
	wg.Add(1)

	// Consumer routine
	go func() {
		defer wg.Done()
		count := 0
		for range buf.Events() {
			count++
			if count >= b.N {
				return
			}
		}
	}()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Push(ev)
	}

	wg.Wait()
}
