package collector

import (
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/executeid/ztre/pkg/observability"
	"github.com/prometheus/client_golang/prometheus"
)

// Parser parses raw Tetragon gRPC responses into normalized SecurityEvents.
type Parser struct{}

// NewParser creates a new EventParser.
func NewParser() *Parser {
	return &Parser{}
}

// Parse extracts structured security attributes from a raw Tetragon GetEventsResponse.
// It returns nil if the event is not relevant (e.g. host-level daemon without Pod metadata).
func (p *Parser) Parse(res *tetragon.GetEventsResponse) (*SecurityEvent, error) {
	if res == nil {
		return nil, nil
	}

	timer := prometheus.NewTimer(observability.EventParseDuration)
	defer timer.ObserveDuration()

	eventTime := time.Now().UTC()
	if res.GetTime() != nil {
		eventTime = res.GetTime().AsTime()
	}

	nodeName := res.GetNodeName()

	switch ev := res.GetEvent().(type) {
	case *tetragon.GetEventsResponse_ProcessExec:
		if ev.ProcessExec == nil {
			return nil, nil
		}
		return p.buildSecurityEvent(ev.ProcessExec.GetProcess(), ev.ProcessExec.GetParent(), EventTypeExecve, nodeName, eventTime), nil

	case *tetragon.GetEventsResponse_ProcessExit:
		if ev.ProcessExit == nil {
			return nil, nil
		}
		return p.buildSecurityEvent(ev.ProcessExit.GetProcess(), ev.ProcessExit.GetParent(), EventTypeExit, nodeName, eventTime), nil

	case *tetragon.GetEventsResponse_ProcessKprobe:
		if ev.ProcessKprobe == nil {
			return nil, nil
		}
		return p.buildSecurityEvent(ev.ProcessKprobe.GetProcess(), ev.ProcessKprobe.GetParent(), EventTypeKprobe, nodeName, eventTime), nil

	default:
		// Other event types (throttling, loader, etc.) can be safely skipped
		return nil, nil
	}
}

func (p *Parser) buildSecurityEvent(
	proc *tetragon.Process,
	parent *tetragon.Process,
	eventType EventType,
	nodeName string,
	eventTime time.Time,
) *SecurityEvent {
	if proc == nil {
		return nil
	}

	pod := proc.GetPod()
	// If the process does not originate from a Kubernetes Pod, we ignore host-level OS noise
	if pod == nil || pod.GetNamespace() == "" {
		return nil
	}

	var pid uint32
	if proc.GetPid() != nil {
		pid = proc.GetPid().GetValue()
	}

	secEvent := &SecurityEvent{
		Timestamp:    eventTime,
		EventType:    eventType,
		PID:          pid,
		Binary:       proc.GetBinary(),
		Arguments:    proc.GetArguments(),
		Namespace:    pod.GetNamespace(),
		PodName:      pod.GetName(),
		NodeName:     nodeName,
		WorkloadKind: pod.GetWorkloadKind(),
		WorkloadName: pod.GetWorkload(),
	}

	if pod.GetContainer() != nil {
		secEvent.ContainerID = pod.GetContainer().GetId()
	}

	if parent != nil {
		if parent.GetPid() != nil {
			secEvent.ParentPID = parent.GetPid().GetValue()
		}
		secEvent.ParentBinary = parent.GetBinary()
	}

	return secEvent
}
