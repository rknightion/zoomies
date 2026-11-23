// Command fakegithub serves the in-process GitHub fake on a loopback port, so
// that a browser can reach it.
//
// The Playwright suite drives the real binary, and everything below the browser
// already runs against `internal/github`'s fake -- but that fake is an
// in-process test server, so the one client that could never reach it was the
// one an operator uses. Connecting an App, verifying it, and watching a runner
// appear were therefore tested at every layer except the page they happen on.
//
// This is that fake with a port. It is a test-only program: it mints nothing,
// verifies no signature, and answers every App as though the credentials were
// perfect, which is exactly what makes it useless to anything but a test and
// safe to point a browser at.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/eyupio/zoomies/internal/github"
)

// controlHandler lets a harness queue a job on the fake: POST /jobs with a JSON
// body naming the repository, workflow, job and runs-on labels. It is how a
// test that drives the real binary makes work appear without a real workflow.
func controlHandler(fake *github.FakeGitHub) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /jobs", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Repo     string   `json:"repo"`
			Workflow string   `json:"workflow"`
			Job      string   `json:"job"`
			Labels   []string `json:"labels"`
		}
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			http.Error(w, "the body must be JSON with repo, workflow, job and labels: "+err.Error(), http.StatusBadRequest)
			return
		}
		if req.Repo == "" || req.Workflow == "" || req.Job == "" {
			http.Error(w, "repo, workflow and job are all required", http.StatusBadRequest)
			return
		}
		job := fake.AddQueuedJob(req.Repo, req.Workflow, req.Job, req.Labels)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(job)
	})
	return mux
}

func main() {
	control := flag.Bool("control", false, "also serve a loopback control route that queues jobs")
	flag.Parse()

	fake := github.NewFake()
	defer fake.Close()

	// Something for a fleet to see. The names match the demo seed's, so a
	// spec that connects this fake and one that reads the seeded fixture are
	// looking at the same organisation.
	for _, repo := range []string{"acme/widgets", "acme/site", "acme/infra"} {
		fake.AddRepo(repo)
	}

	// One line, parsed by the harness that started it: the URL to hand to an
	// installation, and the two identifiers the connect form asks for.
	//
	// No flush: os.Stdout is unbuffered, and asking a pipe to sync fails with
	// "invalid argument" -- which, guarded, exited this program the instant it
	// had said where it was, so the harness read an address nothing was
	// listening on.
	fmt.Printf("fakegithub url=%s app_id=%d installation_id=%d\n",
		fake.URL(), fake.AppID(), fake.InstallationID())

	// Off unless asked for, so the one line above stays the whole of what an
	// existing harness sees. The route is bound to loopback only: it mutates
	// the fake, and nothing off this machine should be able to.
	if *control {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			fmt.Fprintln(os.Stderr, "fakegithub: cannot open the control port:", err)
			os.Exit(1)
		}
		srv := &http.Server{Handler: controlHandler(fake), ReadHeaderTimeout: 5 * time.Second}
		go func() { _ = srv.Serve(ln) }()
		defer srv.Close()
		fmt.Printf("fakegithub control=http://%s\n", ln.Addr())
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
}
