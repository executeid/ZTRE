package collector

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// ClientConfig holds configuration for the Tetragon gRPC client.
type ClientConfig struct {
	SocketPath          string
	ReconnectInterval   time.Duration
	MaxReconnectBackoff time.Duration
}

// Client manages the gRPC connection to Tetragon's FineGuidanceSensors service.
type Client struct {
	config ClientConfig
	parser *Parser
	buffer *EventBuffer
	logger *zap.Logger
}

// NewClient initializes a new TetragonClient.
func NewClient(config ClientConfig, buffer *EventBuffer, logger *zap.Logger) *Client {
	if config.SocketPath == "" {
		config.SocketPath = "unix:///var/run/tetragon/tetragon.sock"
	}
	if !strings.HasPrefix(config.SocketPath, "unix://") && !strings.Contains(config.SocketPath, ":") {
		config.SocketPath = "unix://" + config.SocketPath
	}
	if config.ReconnectInterval <= 0 {
		config.ReconnectInterval = 1 * time.Second
	}
	if config.MaxReconnectBackoff <= 0 {
		config.MaxReconnectBackoff = 10 * time.Second
	}

	return &Client{
		config: config,
		parser: NewParser(),
		buffer: buffer,
		logger: logger,
	}
}

// Start begins streaming events from Tetragon with automatic reconnect.
// It blocks until the context is canceled.
func (c *Client) Start(ctx context.Context) error {
	backoff := c.config.ReconnectInterval

	for {
		select {
		case <-ctx.Done():
			c.logger.Info("stopping Tetragon event stream listener")
			return nil
		default:
		}

		c.logger.Info("connecting to Tetragon gRPC server", zap.String("socket", c.config.SocketPath))
		err := c.streamEvents(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			c.logger.Error("Tetragon event stream disconnected",
				zap.Error(err),
				zap.Duration("retry_in", backoff),
			)
		}

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
			// Exponential backoff up to max
			backoff *= 2
			if backoff > c.config.MaxReconnectBackoff {
				backoff = c.config.MaxReconnectBackoff
			}
		}
	}
}

func (c *Client) streamEvents(ctx context.Context) error {
	conn, err := grpc.NewClient(
		c.config.SocketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return fmt.Errorf("failed to dial Tetragon socket: %w", err)
	}
	defer conn.Close()

	tetragonClient := tetragon.NewFineGuidanceSensorsClient(conn)

	req := &tetragon.GetEventsRequest{}
	stream, err := tetragonClient.GetEvents(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to open Tetragon GetEvents stream: %w", err)
	}

	c.logger.Info("Tetragon gRPC event stream established successfully")

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		res, err := stream.Recv()
		if err == io.EOF {
			return fmt.Errorf("Tetragon stream closed by server (EOF)")
		}
		if err != nil {
			return fmt.Errorf("error reading from Tetragon stream: %w", err)
		}

		event, parseErr := c.parser.Parse(res)
		if parseErr != nil {
			c.logger.Debug("skipping unparseable event", zap.Error(parseErr))
			continue
		}

		if event != nil {
			c.buffer.Push(event)
		}
	}
}
