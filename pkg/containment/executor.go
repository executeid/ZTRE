package containment

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/executeid/ztre/pkg/observability"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/retry"
)

const (
	QuarantineLabelKey   = "ztre/quarantine"
	QuarantineLabelValue = "true"
)

// ContainmentExecutor defines the interface for applying workload containment.
type ContainmentExecutor interface {
	Quarantine(ctx context.Context, namespace, podName string, riskScore float64) error
}

// Executor implements automated pod quarantine via Kubernetes API label patching.
// By adding "ztre/quarantine: true" to pod labels, CiliumNetworkPolicy immediately
// drops all ingress and egress network packets without terminating the container process.
type Executor struct {
	client      kubernetes.Interface
	logger      *zap.Logger
	quarantined sync.Map // map[string]struct{} (key: "namespace/podName")
}

// NewExecutor creates a containment executor with a supplied Kubernetes clientset.
func NewExecutor(client kubernetes.Interface, logger *zap.Logger) *Executor {
	return &Executor{
		client: client,
		logger: logger,
	}
}

// NewInClusterExecutor creates an executor configured for in-cluster DaemonSet execution,
// with graceful fallback to local ~/.kube/config or KUBECONFIG env for local testing.
func NewInClusterExecutor(logger *zap.Logger) (*Executor, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		// Fallback to KUBECONFIG or ~/.kube/config
		kubeconfig := os.Getenv("KUBECONFIG")
		if kubeconfig == "" {
			home, _ := os.UserHomeDir()
			kubeconfig = filepath.Join(home, ".kube", "config")
		}
		var localErr error
		config, localErr = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if localErr != nil {
			return nil, fmt.Errorf("failed to get in-cluster and local k8s config: in-cluster(%w), local(%v)", err, localErr)
		}
		logger.Info("using local kubeconfig for containment executor", zap.String("path", kubeconfig))
	} else {
		logger.Info("using in-cluster serviceaccount for containment executor")
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("create k8s clientset: %w", err)
	}

	return NewExecutor(clientset, logger), nil
}

// Quarantine applies the quarantine label to the target Pod using StrategicMergePatch.
// It executes with exponential retry backoff on API conflicts or transient failures.
// CRITICAL: This operation NEVER terminates the pod or its processes (zero process kill).
func (e *Executor) Quarantine(ctx context.Context, namespace, podName string, riskScore float64) error {
	podKey := fmt.Sprintf("%s/%s", namespace, podName)
	if _, already := e.quarantined.Load(podKey); already {
		e.logger.Debug("pod already in quarantine cache, skipping redundant API patch",
			zap.String("namespace", namespace),
			zap.String("pod", podName),
		)
		return nil
	}

	startTime := time.Now()

	// Strategic merge patch payload to add ztre/quarantine: "true"
	patchMap := map[string]interface{}{
		"metadata": map[string]interface{}{
			"labels": map[string]string{
				QuarantineLabelKey: QuarantineLabelValue,
			},
		},
	}
	patchData, err := json.Marshal(patchMap)
	if err != nil {
		return fmt.Errorf("marshal patch payload: %w", err)
	}

	// Retry with exponential backoff on transient errors (initial 100ms, factor 2.0, max 3 steps)
	backoff := retry.DefaultBackoff
	backoff.Duration = 100 * time.Millisecond
	backoff.Steps = 3

	// isRetryable returns true for transient errors and 409 Conflict.
	// Non-retryable errors (404 Not Found, 422 Invalid) skip retries
	// immediately to avoid unnecessary delay on deleted or invalid pods.
	isRetryable := func(err error) bool {
		if k8serrors.IsNotFound(err) || k8serrors.IsInvalid(err) {
			return false
		}
		return err != nil
	}

	err = retry.OnError(backoff, isRetryable, func() error {
		_, patchErr := e.client.CoreV1().Pods(namespace).Patch(
			ctx,
			podName,
			k8stypes.StrategicMergePatchType,
			patchData,
			metav1.PatchOptions{},
		)
		return patchErr
	})

	latency := time.Since(startTime)

	if err != nil {
		observability.ApiErrorsTotal.Inc()
		e.logger.Error("AUTOMATED CONTAINMENT FAILED",
			zap.String("namespace", namespace),
			zap.String("pod", podName),
			zap.Float64("risk_score", riskScore),
			zap.Duration("latency", latency),
			zap.Error(err),
		)
		return fmt.Errorf("quarantine pod %s/%s failed after retries: %w", namespace, podName, err)
	}

	e.quarantined.Store(podKey, struct{}{})
	observability.ContainmentActionsTotal.Inc()
	e.logger.Info("AUTOMATED CONTAINMENT EXECUTED SUCCESSFULLY",
		zap.String("action", "AUTO_CONTAINMENT"),
		zap.String("namespace", namespace),
		zap.String("pod", podName),
		zap.String("applied_label", fmt.Sprintf("%s=%s", QuarantineLabelKey, QuarantineLabelValue)),
		zap.Float64("risk_score", riskScore),
		zap.Duration("latency", latency),
		zap.String("enforcement", "CiliumNetworkPolicy active (Deny All Ingress/Egress)"),
		zap.String("forensic_status", "Pod preserved running; volatile memory intact (zero process kill)"),
	)

	return nil
}

// IsQuarantined reports whether the pod is recorded in the quarantine cache.
func (e *Executor) IsQuarantined(namespace, podName string) bool {
	_, ok := e.quarantined.Load(fmt.Sprintf("%s/%s", namespace, podName))
	return ok
}

// ResetCache clears the in-memory quarantine cache.
func (e *Executor) ResetCache() {
	e.quarantined.Range(func(key, value any) bool {
		e.quarantined.Delete(key)
		return true
	})
}
