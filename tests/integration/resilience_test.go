package integration_test

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/executeid/ztre/pkg/collector"
	"github.com/executeid/ztre/pkg/containment"
	"github.com/executeid/ztre/pkg/validator"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// 1. HIGH LOAD GRACEFUL DEGRADATION
// Push 50,000 events rapidly into an EventBuffer with capacity 1000.
// Verify buffer drops events gracefully (increments drop counter), does not panic, does not deadlock.
func TestResilience_HighLoad_GracefulDegradation(t *testing.T) {
	logger := zap.NewNop()
	capacity := 1000
	totalEvents := 50000

	buf := collector.NewEventBuffer(capacity, logger)
	defer buf.Close()

	var pushSuccess uint64
	var pushFailed uint64

	const numProducers = 10
	eventsPerProducer := totalEvents / numProducers
	var wg sync.WaitGroup

	for p := 0; p < numProducers; p++ {
		wg.Add(1)
		go func(producerID int) {
			defer wg.Done()
			for i := 0; i < eventsPerProducer; i++ {
				ev := &collector.SecurityEvent{
					EventType:    collector.EventTypeExecve,
					ParentBinary: "/usr/sbin/nginx",
					Binary:       "/bin/ls",
					Namespace:    "test-ns",
					PodName:      fmt.Sprintf("pod-%d-%d", producerID, i),
				}
				if buf.Push(ev) {
					atomic.AddUint64(&pushSuccess, 1)
				} else {
					atomic.AddUint64(&pushFailed, 1)
				}
			}
		}(p)
	}

	doneCh := make(chan struct{})
	go func() {
		wg.Wait()
		close(doneCh)
	}()

	select {
	case <-doneCh:
		// Completed without deadlock
	case <-time.After(10 * time.Second):
		t.Fatal("high load push timed out - potential deadlock detected")
	}

	dropped := buf.DroppedCount()
	buffered := buf.Len()

	if pushSuccess+pushFailed != uint64(totalEvents) {
		t.Fatalf("expected sum of push successes (%d) + failures (%d) to equal total %d",
			pushSuccess, pushFailed, totalEvents)
	}

	if dropped != pushFailed {
		t.Fatalf("expected buffer dropped counter (%d) to equal push failures (%d)", dropped, pushFailed)
	}

	if dropped == 0 {
		t.Fatal("expected buffer drops under 50k push to 1k buffer without consumer, got 0 drops")
	}

	if buffered > capacity {
		t.Fatalf("buffer occupancy %d exceeded capacity %d", buffered, capacity)
	}

	t.Logf("Graceful Degradation Verified: Total=%d, Accepted=%d, Dropped=%d, Buffered=%d",
		totalEvents, pushSuccess, dropped, buffered)
}

// 2. GRACEFUL SHUTDOWN UNDER LOAD
// Start the pipeline with active workers processing events via EventBuffer, then close the buffer.
// Verify all in-flight events complete processing, no goroutine leaks, no panics.
func TestResilience_GracefulShutdown_UnderLoad(t *testing.T) {
	logger := zap.NewNop()
	capacity := 1000
	buf := collector.NewEventBuffer(capacity, logger)

	workerCount := 8
	var processedCount int64
	var workerWg sync.WaitGroup

	// Start workers processing events
	for w := 0; w < workerCount; w++ {
		workerWg.Add(1)
		go func(id int) {
			defer workerWg.Done()
			for ev := range buf.Events() {
				// Simulate lightweight work (classification check)
				if ev != nil && ev.Binary != "" {
					_ = validator.ClassNormal
				}
				atomic.AddInt64(&processedCount, 1)
			}
		}(w)
	}

	// Produce events concurrently from multiple producers
	producerCount := 4
	eventsPerProducer := 2500
	totalExpectedEvents := int64(producerCount * eventsPerProducer)
	var producerWg sync.WaitGroup
	var acceptedCount int64

	for p := 0; p < producerCount; p++ {
		producerWg.Add(1)
		go func(id int) {
			defer producerWg.Done()
			for i := 0; i < eventsPerProducer; i++ {
				ev := &collector.SecurityEvent{
					EventType:    collector.EventTypeExecve,
					ParentBinary: "systemd",
					Binary:       "cron",
					Namespace:    "default",
					PodName:      fmt.Sprintf("worker-pod-%d-%d", id, i),
				}
				// Retry push if buffer temporarily full so all events are accepted
				for {
					if buf.Push(ev) {
						atomic.AddInt64(&acceptedCount, 1)
						break
					}
					time.Sleep(10 * time.Microsecond)
				}
			}
		}(p)
	}

	// Wait for all producers to finish pushing
	producerWg.Wait()

	// Initiate graceful shutdown under active consumer load:
	// Close event buffer - channel is closed, workers must drain all queued events and exit
	buf.Close()

	// Ensure duplicate close does not panic
	buf.Close()

	// Wait for all workers to finish processing queued events
	workerDone := make(chan struct{})
	go func() {
		workerWg.Wait()
		close(workerDone)
	}()

	select {
	case <-workerDone:
		// Clean worker shutdown without hanging
	case <-time.After(10 * time.Second):
		t.Fatal("worker pool shutdown timed out - goroutine leak or hang")
	}

	finalProcessed := atomic.LoadInt64(&processedCount)
	if finalProcessed != totalExpectedEvents {
		t.Fatalf("expected all accepted events to be processed, accepted=%d processed=%d",
			acceptedCount, finalProcessed)
	}

	// Verify pushing after close returns false without panic
	postCloseEv := &collector.SecurityEvent{
		EventType: collector.EventTypeExecve,
		Binary:    "/bin/echo",
	}
	if buf.Push(postCloseEv) {
		t.Fatal("expected Push after Close to return false")
	}

	t.Logf("Graceful Shutdown Verified: Accepted=%d, Processed=%d, All %d workers exited cleanly",
		acceptedCount, finalProcessed, workerCount)
}

// 3. CONTAINMENT RETRY VERIFICATION
// Test that the containment executor properly retries on transient API errors,
// succeeds when transient error clears, and stops without retry on non-retryable errors (e.g. 404).
func TestResilience_ContainmentRetry_TransientFailureRecovers(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "victim-pod",
			Namespace: "prod-db",
			Labels: map[string]string{
				"app": "postgres",
			},
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
		},
	}

	fakeClient := fake.NewSimpleClientset(pod)
	logger := zap.NewNop()
	executor := containment.NewExecutor(fakeClient, logger)

	// Inject 2 transient 500 InternalServerErrors before succeeding.
	// Default retry backoff allows 3 steps (step 1: fail, step 2: fail, step 3: success).
	var callCount int32
	fakeClient.PrependReactor("patch", "pods", func(action k8stesting.Action) (bool, runtime.Object, error) {
		count := atomic.AddInt32(&callCount, 1)
		if count <= 2 {
			return true, nil, k8serrors.NewInternalError(fmt.Errorf("transient etcd leader election in progress"))
		}
		// Pass to default fake tracker for successful patch
		return false, nil, nil
	})

	err := executor.Quarantine(context.Background(), "prod-db", "victim-pod", 95.0)
	if err != nil {
		t.Fatalf("expected quarantine to succeed after retrying transient errors, got error: %v", err)
	}

	totalAttempts := atomic.LoadInt32(&callCount)
	if totalAttempts != 3 {
		t.Fatalf("expected 3 patch attempts (2 retried failures + 1 success), got %d", totalAttempts)
	}

	// Verify pod was quarantined
	updatedPod, err := fakeClient.CoreV1().Pods("prod-db").Get(context.Background(), "victim-pod", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("failed to get pod: %v", err)
	}
	if updatedPod.Labels[containment.QuarantineLabelKey] != containment.QuarantineLabelValue {
		t.Fatalf("expected quarantine label %s=%s, got %s",
			containment.QuarantineLabelKey, containment.QuarantineLabelValue,
			updatedPod.Labels[containment.QuarantineLabelKey])
	}

	t.Logf("Containment Transient Retry Verified: Attempts=%d, Final Status=SUCCESS", totalAttempts)
}

func TestResilience_ContainmentRetry_ExhaustionReturnsError(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "victim-pod-2",
			Namespace: "prod-db",
		},
	}

	fakeClient := fake.NewSimpleClientset(pod)
	logger := zap.NewNop()
	executor := containment.NewExecutor(fakeClient, logger)

	// Always return transient error exceeding retry limit (3 steps)
	var callCount int32
	fakeClient.PrependReactor("patch", "pods", func(action k8stesting.Action) (bool, runtime.Object, error) {
		atomic.AddInt32(&callCount, 1)
		return true, nil, k8serrors.NewServiceUnavailable("kube-apiserver overloaded")
	})

	err := executor.Quarantine(context.Background(), "prod-db", "victim-pod-2", 90.0)
	if err == nil {
		t.Fatal("expected quarantine error after retry exhaustion, got nil")
	}

	totalAttempts := atomic.LoadInt32(&callCount)
	if totalAttempts != 3 {
		t.Fatalf("expected exactly 3 retry attempts before exhaustion, got %d", totalAttempts)
	}

	t.Logf("Containment Retry Exhaustion Verified: Attempts=%d, Error=%v", totalAttempts, err)
}

func TestResilience_ContainmentRetry_NonRetryableSkipsRetries(t *testing.T) {
	fakeClient := fake.NewSimpleClientset()
	logger := zap.NewNop()
	executor := containment.NewExecutor(fakeClient, logger)

	// Inject NotFound error (404)
	var callCount int32
	fakeClient.PrependReactor("patch", "pods", func(action k8stesting.Action) (bool, runtime.Object, error) {
		atomic.AddInt32(&callCount, 1)
		return true, nil, k8serrors.NewNotFound(schema.GroupResource{Resource: "pods"}, "deleted-pod")
	})

	err := executor.Quarantine(context.Background(), "prod-db", "deleted-pod", 85.0)
	if err == nil {
		t.Fatal("expected error on NotFound, got nil")
	}

	totalAttempts := atomic.LoadInt32(&callCount)
	if totalAttempts != 1 {
		t.Fatalf("expected non-retryable error (NotFound) to fail immediately in 1 attempt, got %d", totalAttempts)
	}

	t.Logf("Containment Non-Retryable Fast Fail Verified: Attempts=%d, Error=%v", totalAttempts, err)
}
