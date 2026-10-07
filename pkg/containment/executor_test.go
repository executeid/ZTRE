package containment

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"sync/atomic"
)

func TestQuarantine_SuccessfulPatch(t *testing.T) {
	// Create mock pod in namespace "ztre-test"
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "vulnerable-web",
			Namespace: "ztre-test",
			Labels: map[string]string{
				"app": "frontend",
			},
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
		},
	}

	fakeClient := fake.NewSimpleClientset(pod)
	logger, _ := zap.NewDevelopment()
	executor := NewExecutor(fakeClient, logger)

	err := executor.Quarantine(context.Background(), "ztre-test", "vulnerable-web", 85.0)
	if err != nil {
		t.Fatalf("expected successful quarantine, got error: %v", err)
	}

	// Fetch updated pod from fake client
	updatedPod, err := fakeClient.CoreV1().Pods("ztre-test").Get(context.Background(), "vulnerable-web", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("failed to fetch updated pod: %v", err)
	}

	// Verify quarantine label exists
	val, ok := updatedPod.Labels[QuarantineLabelKey]
	if !ok || val != QuarantineLabelValue {
		t.Errorf("expected label %s=%s, got %s (exists=%v)", QuarantineLabelKey, QuarantineLabelValue, val, ok)
	}

	// Verify original label wasn't wiped out (merge patch preservation)
	if updatedPod.Labels["app"] != "frontend" {
		t.Errorf("expected original label 'app: frontend' to be preserved, got %s", updatedPod.Labels["app"])
	}
}

func TestQuarantine_PodNotFound(t *testing.T) {
	fakeClient := fake.NewSimpleClientset()
	logger := zap.NewNop()
	executor := NewExecutor(fakeClient, logger)

	err := executor.Quarantine(context.Background(), "ztre-test", "nonexistent-pod", 90.0)
	if err == nil {
		t.Fatalf("expected error when pod does not exist, got nil")
	}
}

// TestSafety_NoProcessKillInCodebase verifies PRD NFR-01: Zero process kill commands
// exist in the ZTRE agent codebase (only network quarantine label patching allowed).
func TestSafety_NoProcessKillInCodebase(t *testing.T) {
	rootPath := "../../"

	forbiddenPatterns := []string{
		"syscall.SIGKILL",
		"SIGKILL",
		"syscall.Kill",
		"unix.Kill",
		"os.Kill",
	}

	err := filepath.Walk(rootPath, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			name := info.Name()
			if name == ".git" || name == "bin" || name == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}

		if !strings.HasSuffix(path, ".go") {
			return nil
		}

		// Skip this test file itself so checking forbidden words doesn't fail
		if strings.HasSuffix(path, "executor_test.go") {
			return nil
		}

		content, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}

		for _, forbidden := range forbiddenPatterns {
			if strings.Contains(string(content), forbidden) {
				t.Errorf("CRITICAL SAFETY VIOLATION (NFR-01): File %s contains forbidden process-kill construct %q", path, forbidden)
			}
		}
		return nil
	})

	if err != nil {
		t.Fatalf("failed to scan codebase for safety: %v", err)
	}
}

// TestQuarantine_Idempotent verifies that patching an already-quarantined pod
// (label already present) succeeds without error.
func TestQuarantine_Idempotent(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "already-quarantined",
			Namespace: "ztre-test",
			Labels: map[string]string{
				"app":               "frontend",
				QuarantineLabelKey: QuarantineLabelValue, // already quarantined
			},
		},
	}
	fakeClient := fake.NewSimpleClientset(pod)
	executor := NewExecutor(fakeClient, zap.NewNop())

	// First call
	if err := executor.Quarantine(context.Background(), "ztre-test", "already-quarantined", 85.0); err != nil {
		t.Fatalf("first quarantine should succeed: %v", err)
	}
	// Second call — idempotent
	if err := executor.Quarantine(context.Background(), "ztre-test", "already-quarantined", 90.0); err != nil {
		t.Fatalf("idempotent quarantine should succeed: %v", err)
	}
}

// TestQuarantine_ContextCancelled verifies that a cancelled context causes
// Quarantine to return an error promptly (no hang inside retry loop).
func TestQuarantine_ContextCancelled(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "ctx-test", Namespace: "ztre-test",
			Labels: map[string]string{"app": "frontend"},
		},
	}
	fakeClient := fake.NewSimpleClientset(pod)
	executor := NewExecutor(fakeClient, zap.NewNop())

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	// The fake client may or may not honour context cancellation but Quarantine
	// must return (not hang) — and the fake client does return immediately.
	// This test guards against future changes to real client behaviour.
	done := make(chan error, 1)
	go func() {
		done <- executor.Quarantine(ctx, "ztre-test", "ctx-test", 85.0)
	}()
	select {
	case <-done:
		// returned — acceptable (fake ignores ctx cancellation, patch succeeds)
	case <-time.After(3 * time.Second):
		t.Fatal("Quarantine hung on cancelled context")
	}
}

func TestQuarantine_DeduplicationCache(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "dedup-test",
			Namespace: "ztre-test",
			Labels:    map[string]string{"app": "frontend"},
		},
	}
	fakeClient := fake.NewSimpleClientset(pod)
	var patchCount int32
	fakeClient.PrependReactor("patch", "pods", func(action k8stesting.Action) (bool, runtime.Object, error) {
		atomic.AddInt32(&patchCount, 1)
		return false, nil, nil
	})

	executor := NewExecutor(fakeClient, zap.NewNop())

	// First call should execute patch
	if err := executor.Quarantine(context.Background(), "ztre-test", "dedup-test", 80.0); err != nil {
		t.Fatalf("first call failed: %v", err)
	}
	if atomic.LoadInt32(&patchCount) != 1 {
		t.Fatalf("expected 1 patch call, got %d", atomic.LoadInt32(&patchCount))
	}
	if !executor.IsQuarantined("ztre-test", "dedup-test") {
		t.Fatal("expected pod to be tracked in quarantine cache")
	}

	// Subsequent calls should hit cache and NOT invoke K8s API patch
	for i := 0; i < 5; i++ {
		if err := executor.Quarantine(context.Background(), "ztre-test", "dedup-test", 85.0); err != nil {
			t.Fatalf("cached call %d failed: %v", i, err)
		}
	}
	if atomic.LoadInt32(&patchCount) != 1 {
		t.Fatalf("expected patchCount to remain 1 after cached calls, got %d", atomic.LoadInt32(&patchCount))
	}
}

func TestQuarantine_ConflictRetried(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "conflict-test",
			Namespace: "ztre-test",
			Labels:    map[string]string{"app": "frontend"},
		},
	}
	fakeClient := fake.NewSimpleClientset(pod)
	var attempts int32
	fakeClient.PrependReactor("patch", "pods", func(action k8stesting.Action) (bool, runtime.Object, error) {
		att := atomic.AddInt32(&attempts, 1)
		if att < 3 {
			return true, nil, k8serrors.NewConflict(schema.GroupResource{Resource: "pods"}, "conflict-test", nil)
		}
		return false, nil, nil
	})

	executor := NewExecutor(fakeClient, zap.NewNop())
	err := executor.Quarantine(context.Background(), "ztre-test", "conflict-test", 85.0)
	if err != nil {
		t.Fatalf("expected retry on conflict to eventually succeed, got: %v", err)
	}
	if atomic.LoadInt32(&attempts) != 3 {
		t.Fatalf("expected 3 attempts before conflict resolved, got %d", atomic.LoadInt32(&attempts))
	}
}