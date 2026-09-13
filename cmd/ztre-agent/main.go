package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	fmt.Println("ZTRE Agent started - Zero-Trust Runtime Enforcement")

	// Set up signal handler for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	fmt.Println("Agent initialized. Press Ctrl+C to stop.")
	sig := <-sigChan
	fmt.Printf("Received signal %s, shutting down ZTRE Agent gracefully.\n", sig)
}
