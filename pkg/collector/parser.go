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

	switch ev := res.GetEvent().(type) {
	case *tetragon.GetEventsResponse_ProcessExec:
		exec := ev.ProcessExec
		if exec == nil || exec.GetProcess() == nil {
			return nil, nil
		}

		proc := exec.GetProcess()
		parent := exec.GetParent()
		pod := proc.GetPod()

		// If the process does not originate from a Kubernetes Pod, we ignore host-level OS noise
		if pod == nil || pod.GetNamespace() == "" {
			return nil, nil
		}

		secEvent := &SecurityEvent{
			Timestamp:    eventTime,
			EventType:    EventTypeExecve,
			PID:          proc.GetPid().GetValue(),
			Binary:       proc.GetBinary(),
			Arguments:    proc.GetArguments(),
			Namespace:    pod.GetNamespace(),
			PodName:      pod.GetName(),
			NodeName:     res.GetNodeName(),
			WorkloadKind: pod.GetWorkloadKind(),
			WorkloadName: pod.GetWorkload(),
			RawResponse:  res,
		}

		if pod.GetContainer() != nil {
			secEvent.ContainerID = pod.GetContainer().GetId()
		}

		if parent != nil {
			secEvent.ParentPID = parent.GetPid().GetValue()
			secEvent.ParentBinary = parent.GetBinary()
		}

		return secEvent, nil

	case *tetragon.GetEventsResponse_ProcessExit:
		exit := ev.ProcessExit
		if exit == nil || exit.GetProcess() == nil {
			return nil, nil
		}

		proc := exit.GetProcess()
		pod := proc.GetPod()
		if pod == nil || pod.GetNamespace() == "" {
			return nil, nil
		}

		secEvent := &SecurityEvent{
			Timestamp:    eventTime,
			EventType:    EventTypeExit,
			PID:          proc.GetPid().GetValue(),
			Binary:       proc.GetBinary(),
			Arguments:    proc.GetArguments(),
			Namespace:    pod.GetNamespace(),
			PodName:      pod.GetName(),
			NodeName:     res.GetNodeName(),
			WorkloadKind: pod.GetWorkloadKind(),
			WorkloadName: pod.GetWorkload(),
			RawResponse:  res,
		}

		return secEvent, nil

	case *tetragon.GetEventsResponse_ProcessKprobe:
		kprobe := ev.ProcessKprobe
		if kprobe == nil || kprobe.GetProcess() == nil {
			return nil, nil
		}

		proc := kprobe.GetProcess()
		pod := proc.GetPod()
		if pod == nil || pod.GetNamespace() == "" {
			return nil, nil
		}

		secEvent := &SecurityEvent{
			Timestamp:    eventTime,
			EventType:    EventTypeKprobe,
			PID:          proc.GetPid().GetValue(),
			Binary:       proc.GetBinary(),
			Arguments:    proc.GetArguments(),
			Namespace:    pod.GetNamespace(),
			PodName:      pod.GetName(),
			NodeName:     res.GetNodeName(),
			WorkloadKind: pod.GetWorkloadKind(),
			WorkloadName: pod.GetWorkload(),
			RawResponse:  res,
		}

		if pod.GetContainer() != nil {
			secEvent.ContainerID = pod.GetContainer().GetId()
		}

		if parent := kprobe.GetParent(); parent != nil {
			secEvent.ParentPID = parent.GetPid().GetValue()
			secEvent.ParentBinary = parent.GetBinary()
		}

		return secEvent, nil

	default:
		// Other event types (throttling, loader, etc.) can be safely skipped
		return nil, nil
	}
}
