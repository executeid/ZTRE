package decision

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/executeid/ztre/pkg/observability"
	"go.uber.org/zap"
)

// AlertSink is an interface for alert destinations (stdout, webhook, SIEM).
type AlertSink interface {
	Name() string
	Send(ctx context.Context, alert Alert) error
}

// StdoutAlertSink writes JSON-serialized alerts to stdout / structured logger.
type StdoutAlertSink struct {
	logger *zap.Logger
}

// NewStdoutAlertSink creates a sink that logs alerts via Zap.
func NewStdoutAlertSink(logger *zap.Logger) *StdoutAlertSink {
	return &StdoutAlertSink{logger: logger}
}

func (s *StdoutAlertSink) Name() string {
	return "stdout"
}

func (s *StdoutAlertSink) Send(_ context.Context, alert Alert) error {
	s.logger.Info("SECURITY ALERT EMITTED",
		zap.String("sink", s.Name()),
		zap.String("action", string(alert.Action)),
		zap.String("namespace", alert.Namespace),
		zap.String("pod", alert.PodName),
		zap.String("parent", alert.ParentBinary),
		zap.String("binary", alert.Binary),
		zap.String("args", alert.Arguments),
		zap.String("classification", string(alert.Classification)),
		zap.Float64("risk_score", alert.TotalRiskScore),
		zap.String("recommended_action", alert.RecommendedAction),
	)
	return nil
}

// WebhookAlertSink dispatches alerts via HTTP POST to a remote endpoint.
type WebhookAlertSink struct {
	url        string
	client     *http.Client
	extraHeaders map[string]string
}

// NewWebhookAlertSink creates a webhook sink with configurable timeout.
func NewWebhookAlertSink(url string, timeout time.Duration, headers map[string]string) *WebhookAlertSink {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &WebhookAlertSink{
		url: url,
		client: &http.Client{
			Timeout: timeout,
		},
		extraHeaders: headers,
	}
}

func (w *WebhookAlertSink) Name() string {
	return "webhook"
}

func (w *WebhookAlertSink) Send(ctx context.Context, alert Alert) error {
	data, err := json.Marshal(alert)
	if err != nil {
		return fmt.Errorf("marshal alert: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("create webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range w.extraHeaders {
		req.Header.Set(k, v)
	}

	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook post failed: %w", err)
	}
	// Drain body before closing so the underlying TCP connection can be reused
	// by the HTTP keep-alive pool.
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook responded with non-2xx status: %d", resp.StatusCode)
	}

	return nil
}

// Dispatcher broadcasts security alerts to all registered AlertSinks.
type Dispatcher struct {
	mu     sync.RWMutex
	sinks  []AlertSink
	logger *zap.Logger
}

// NewDispatcher creates an AlertDispatcher.
func NewDispatcher(logger *zap.Logger, initialSinks ...AlertSink) *Dispatcher {
	d := &Dispatcher{
		sinks:  make([]AlertSink, 0),
		logger: logger,
	}
	for _, s := range initialSinks {
		d.RegisterSink(s)
	}
	return d
}

// RegisterSink registers an AlertSink.
func (d *Dispatcher) RegisterSink(sink AlertSink) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.sinks = append(d.sinks, sink)
	d.logger.Info("registered alert sink", zap.String("sink", sink.Name()))
}

// Sinks returns the current list of registered sinks.
func (d *Dispatcher) Sinks() []AlertSink {
	d.mu.RLock()
	defer d.mu.RUnlock()
	res := make([]AlertSink, len(d.sinks))
	copy(res, d.sinks)
	return res
}

// Dispatch sends the alert to all registered sinks concurrently.
// Panics inside individual sink goroutines are recovered and logged
// to prevent a misbehaving sink from crashing the agent process.
func (d *Dispatcher) Dispatch(ctx context.Context, alert Alert) {
	d.mu.RLock()
	sinks := append([]AlertSink(nil), d.sinks...)
	d.mu.RUnlock()

	var wg sync.WaitGroup
	for _, sink := range sinks {
		s := sink
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					d.logger.Error("panic recovered in alert sink goroutine",
						zap.String("sink", s.Name()),
						zap.Any("panic", r),
					)
				}
			}()
			if err := s.Send(ctx, alert); err != nil {
				d.logger.Error("failed to dispatch alert to sink",
					zap.String("sink", s.Name()),
					zap.String("pod", alert.PodName),
					zap.Error(err),
				)
			} else {
				observability.AlertsDispatchedTotal.WithLabelValues(s.Name()).Inc()
			}
		}()
	}
	wg.Wait()
}
