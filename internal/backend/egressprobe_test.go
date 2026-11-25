package backend

import (
	"bytes"
	"context"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The probe says what the guest's helper says, in words the same parser reads,
// and only a timeout passes a must-block target.
func TestEgressProbeClassifiesEachOutcomeAsTheGuestDoes(t *testing.T) {
	open, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { open.Close() })
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedAddr := closed.Addr().String()
	closed.Close()

	targets := []string{open.Addr().String(), closedAddr, "no-port", "127.0.0.1:0", "127.0.0.1:99999"}
	var out bytes.Buffer
	if err := EgressProbe(context.Background(), &out, time.Second, targets); err != nil {
		t.Fatal(err)
	}
	got, err := parseVMPalEgress(out.String(), len(targets))
	if err != nil {
		t.Fatalf("the agent cannot read %q: %v", out.String(), err)
	}
	want := []string{vmpalEgressConnected, vmpalEgressRefused, vmpalEgressError, vmpalEgressError, vmpalEgressError}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("target %q: %s, want %s", targets[i], got[i], want[i])
		}
	}
	if !strings.HasSuffix(out.String(), "zoomies-egress v1 end 5\n") {
		t.Errorf("output = %q", out.String())
	}
}

func TestClassifyEgressErrorNamesEveryWayAConnectionEnds(t *testing.T) {
	op := func(err error) error { return &net.OpError{Op: "dial", Err: os.NewSyscallError("connect", err)} }
	cases := []struct {
		err  error
		want string
	}{
		{op(syscall.ECONNREFUSED), vmpalEgressRefused},
		{op(syscall.ENETUNREACH), vmpalEgressUnreachable},
		{op(syscall.EHOSTUNREACH), vmpalEgressUnreachable},
		{op(syscall.ETIMEDOUT), vmpalEgressTimeout},
		{context.DeadlineExceeded, vmpalEgressTimeout},
		{&net.OpError{Op: "dial", Err: os.ErrDeadlineExceeded}, vmpalEgressTimeout},
		{op(syscall.EACCES), vmpalEgressError},
		{op(syscall.ECONNRESET), vmpalEgressError},
	}
	for _, tc := range cases {
		if got := classifyEgressError(tc.err); got != tc.want {
			t.Errorf("%v: %s, want %s", tc.err, got, tc.want)
		}
	}
}

func TestEgressProbeWithNoTargetsStillPrintsItsEnd(t *testing.T) {
	var out bytes.Buffer
	if err := EgressProbe(context.Background(), &out, time.Second, nil); err != nil {
		t.Fatal(err)
	}
	if out.String() != "zoomies-egress v1 end 0\n" {
		t.Errorf("output = %q", out.String())
	}
}
