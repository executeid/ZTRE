package testutil

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/executeid/ztre/pkg/collector"
)

func TestEventFactory_MakeEvent(t *testing.T) {
	ts := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)
	ev := MakeEvent("nginx", "bash", "prod", "web-frontend", "k8s-node-1",
		WithTimestamp(ts),
		WithPID(5000, 100),
		WithArguments("-l"),
		WithContainerID("cid-999"),
		WithWorkloadKind("StatefulSet"),
	)

	if ev.EventType != collector.EventTypeExecve {
		t.Fatalf("expected EventTypeExecve, got %s", ev.EventType)
	}
	if ev.Binary != "/usr/bin/bash" {
		t.Errorf("expected /usr/bin/bash, got %s", ev.Binary)
	}
	if ev.ParentBinary != "/usr/sbin/nginx" {
		t.Errorf("expected /usr/sbin/nginx, got %s", ev.ParentBinary)
	}
	if ev.Namespace != "prod" {
		t.Errorf("expected prod, got %s", ev.Namespace)
	}
	if ev.WorkloadName != "web-frontend" {
		t.Errorf("expected web-frontend, got %s", ev.WorkloadName)
	}
	if ev.WorkloadKind != "StatefulSet" {
		t.Errorf("expected StatefulSet, got %s", ev.WorkloadKind)
	}
	if ev.PID != 5000 || ev.ParentPID != 100 {
		t.Errorf("expected pid 5000/100, got %d/%d", ev.PID, ev.ParentPID)
	}
	if ev.Arguments != "-l" {
		t.Errorf("expected -l, got %s", ev.Arguments)
	}
	if ev.ContainerID != "cid-999" {
		t.Errorf("expected cid-999, got %s", ev.ContainerID)
	}
	if !ev.Timestamp.Equal(ts) {
		t.Errorf("expected timestamp %v, got %v", ts, ev.Timestamp)
	}
}

func TestTetragonMockServer_Streaming(t *testing.T) {
	mockServer := StartTetragonMockServer()
	defer mockServer.Stop()

	execResp := NewTetragonExecResponse("/usr/sbin/nginx", "/bin/bash", "default", "web", "worker-1")
	exitResp := NewTetragonExitResponse("/bin/bash", "default", "web", "worker-1")

	mockServer.Mock.AddResponse(execResp)
	mockServer.Mock.AddResponse(exitResp)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	conn, err := mockServer.NewClientConn(ctx)
	if err != nil {
		t.Fatalf("failed to create client conn: %v", err)
	}
	defer conn.Close()

	client := tetragon.NewFineGuidanceSensorsClient(conn)
	stream, err := client.GetEvents(ctx, &tetragon.GetEventsRequest{})
	if err != nil {
		t.Fatalf("GetEvents stream error: %v", err)
	}

	parser := collector.NewParser()
	var receivedEvents []*collector.SecurityEvent

	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("stream recv error: %v", err)
		}
		secEv, parseErr := parser.Parse(msg)
		if parseErr != nil {
			t.Fatalf("parser error: %v", parseErr)
		}
		if secEv != nil {
			receivedEvents = append(receivedEvents, secEv)
		}
	}

	if len(receivedEvents) != 2 {
		t.Fatalf("expected 2 received events, got %d", len(receivedEvents))
	}

	if receivedEvents[0].EventType != collector.EventTypeExecve {
		t.Errorf("first event should be execve, got %s", receivedEvents[0].EventType)
	}
	if receivedEvents[0].Binary != "/bin/bash" {
		t.Errorf("expected /bin/bash, got %s", receivedEvents[0].Binary)
	}
	if receivedEvents[0].ParentBinary != "/usr/sbin/nginx" {
		t.Errorf("expected /usr/sbin/nginx, got %s", receivedEvents[0].ParentBinary)
	}

	if receivedEvents[1].EventType != collector.EventTypeExit {
		t.Errorf("second event should be exit, got %s", receivedEvents[1].EventType)
	}
}
