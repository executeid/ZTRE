// Command vulnerable-web is an intentionally-insecure HTTP service used by the
// ZTRE advanced outsider-attack simulation (doc/ADVANCED_TEST_PLAN.md).
//
// It is a *test fixture*, not production code. It exposes a deliberately
// command-injection endpoint so that an external HTTP client can trigger
// process creation inside the container. This reproduces the realistic
// outsider lineage:
//
//	vulnerable-web (Go server) -> /bin/sh -c "<cmd>" -> <payload>
//
// which is fundamentally different from `kubectl exec` (runc -> sh -> payload).
//
// Endpoints:
//
//	GET /healthz                     -> 200 OK
//	GET /exec?cmd=<command>          -> runs <command> via /bin/sh -c, returns output
//
// The server deliberately spawns /bin/sh -c so that Tetragon observes a real
// shell parent for the payload, matching how a shell-injection RCE behaves.
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"time"
)

func main() {
	addr := ":8080"

	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "ok\n")
	})

	// DELIBERATELY VULNERABLE: unauthenticated command execution.
	mux.HandleFunc("/exec", func(w http.ResponseWriter, r *http.Request) {
		cmdStr := r.URL.Query().Get("cmd")
		if cmdStr == "" {
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, "ready\n")
			return
		}

		// Bound the runtime so a stuck payload (e.g. a reverse shell that never
		// connects) cannot wedge the handler forever.
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()

		out, err := exec.CommandContext(ctx, "/bin/sh", "-c", cmdStr).CombinedOutput()

		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "%s", string(out))
		if err != nil {
			fmt.Fprintf(w, "\n[exit: %v]\n", err)
		}
	})

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("[vulnerable-web] listening on %s (RCE endpoint: /exec?cmd=...)", addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
}
