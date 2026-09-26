package testutil

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const bufSize = 1024 * 1024

// MockTetragonServer implements the Tetragon FineGuidanceSensors gRPC service.
type MockTetragonServer struct {
	tetragon.UnimplementedFineGuidanceSensorsServer
	mu        sync.Mutex
	responses []*tetragon.GetEventsResponse
}

// NewMockTetragonServer creates a new MockTetragonServer instance.
func NewMockTetragonServer() *MockTetragonServer {
	return &MockTetragonServer{
		responses: make([]*tetragon.GetEventsResponse, 0),
	}
}

// AddResponse enqueues a GetEventsResponse to be emitted during streaming.
func (s *MockTetragonServer) AddResponse(res *tetragon.GetEventsResponse) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.responses = append(s.responses, res)
}

// SetResponses replaces all pending responses with the provided list.
func (s *MockTetragonServer) SetResponses(resps []*tetragon.GetEventsResponse) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.responses = append([]*tetragon.GetEventsResponse(nil), resps...)
}

// ClearResponses removes all queued responses.
func (s *MockTetragonServer) ClearResponses() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.responses = nil
}

// GetEvents streams configured Tetragon events to the client.
func (s *MockTetragonServer) GetEvents(req *tetragon.GetEventsRequest, stream grpc.ServerStreamingServer[tetragon.GetEventsResponse]) error {
	s.mu.Lock()
	resps := append([]*tetragon.GetEventsResponse(nil), s.responses...)
	s.mu.Unlock()

	for _, res := range resps {
		if err := stream.Context().Err(); err != nil {
			return err
		}
		if err := stream.Send(res); err != nil {
			return err
		}
	}
	return nil
}

// TetragonMockServer hosts an in-memory gRPC server backed by bufconn.
type TetragonMockServer struct {
	Server   *grpc.Server
	Listener *bufconn.Listener
	Mock     *MockTetragonServer
}

// StartTetragonMockServer starts an in-memory Tetragon gRPC server.
func StartTetragonMockServer() *TetragonMockServer {
	lis := bufconn.Listen(bufSize)
	srv := grpc.NewServer()
	mock := NewMockTetragonServer()
	tetragon.RegisterFineGuidanceSensorsServer(srv, mock)

	go func() {
		_ = srv.Serve(lis)
	}()

	return &TetragonMockServer{
		Server:   srv,
		Listener: lis,
		Mock:     mock,
	}
}

// Stop stops the mock gRPC server and closes the buffer listener.
func (m *TetragonMockServer) Stop() {
	m.Server.Stop()
	_ = m.Listener.Close()
}

// Dialer returns a dialer function suitable for grpc.WithContextDialer.
func (m *TetragonMockServer) Dialer() func(context.Context, string) (net.Conn, error) {
	return func(context.Context, string) (net.Conn, error) {
		return m.Listener.Dial()
	}
}

// NewClientConn creates an in-memory gRPC ClientConn connected to this mock server.
func (m *TetragonMockServer) NewClientConn(ctx context.Context) (*grpc.ClientConn, error) {
	return grpc.NewClient(
		"passthrough://bufnet",
		grpc.WithContextDialer(m.Dialer()),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
}

// NewTetragonExecResponseWithArgs builds a GetEventsResponse containing a ProcessExec event with custom arguments.
func NewTetragonExecResponseWithArgs(parentBinary, childBinary, args, namespace, workload, node string) *tetragon.GetEventsResponse {
	return &tetragon.GetEventsResponse{
		NodeName: node,
		Time:     timestamppb.New(time.Now().UTC()),
		Event: &tetragon.GetEventsResponse_ProcessExec{
			ProcessExec: &tetragon.ProcessExec{
				Process: &tetragon.Process{
					Pid:       wrapperspb.UInt32(1234),
					Binary:    childBinary,
					Arguments: args,
					Pod: &tetragon.Pod{
						Namespace:    namespace,
						Name:         workload + "-pod-xyz",
						Workload:     workload,
						WorkloadKind: "Deployment",
						Container: &tetragon.Container{
							Id: "containerd://mock123",
						},
					},
				},
				Parent: &tetragon.Process{
					Pid:    wrapperspb.UInt32(1000),
					Binary: parentBinary,
				},
			},
		},
	}
}

// NewTetragonExecResponse builds a GetEventsResponse containing a ProcessExec event.
func NewTetragonExecResponse(parentBinary, childBinary, namespace, workload, node string) *tetragon.GetEventsResponse {
	return NewTetragonExecResponseWithArgs(parentBinary, childBinary, "-c run", namespace, workload, node)
}

// NewTetragonExitResponse builds a GetEventsResponse containing a ProcessExit event.
func NewTetragonExitResponse(binary, namespace, workload, node string) *tetragon.GetEventsResponse {
	return &tetragon.GetEventsResponse{
		NodeName: node,
		Time:     timestamppb.New(time.Now().UTC()),
		Event: &tetragon.GetEventsResponse_ProcessExit{
			ProcessExit: &tetragon.ProcessExit{
				Process: &tetragon.Process{
					Pid:    wrapperspb.UInt32(1234),
					Binary: binary,
					Pod: &tetragon.Pod{
						Namespace:    namespace,
						Name:         workload + "-pod-xyz",
						Workload:     workload,
						WorkloadKind: "Deployment",
					},
				},
			},
		},
	}
}
