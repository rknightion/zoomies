package backend

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"syscall"
	"time"
)

// EgressProbe is what `zoomies agent egress-probe` runs. It tries one TCP
// connection to each target and prints, for each, the same one-line answers the
// VM guest's helper prints, which the agent reads with the same parser. It is
// run as a job user by the agent before that user's job starts, so what it finds
// is what a job would find.
//
// Every target is tried, in order, because a must-block target that answers is
// the result that matters most, and an answer cut short could leave out the one
// that connected.
func EgressProbe(ctx context.Context, w io.Writer, timeout time.Duration, targets []string) error {
	for i, target := range targets {
		if _, err := fmt.Fprintf(w, "zoomies-egress v1 target %d %s\n", i, probeTarget(ctx, timeout, target)); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintf(w, "zoomies-egress v1 end %d\n", len(targets))
	return err
}

// probeTarget makes one attempt and says how it ended.
func probeTarget(ctx context.Context, timeout time.Duration, target string) string {
	host, port, err := net.SplitHostPort(target)
	if err != nil || host == "" {
		return vmpalEgressError
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return vmpalEgressError
	}
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		return classifyEgressError(err)
	}
	_ = conn.Close()
	return vmpalEgressConnected
}

// classifyEgressError names a failed connection the way the guest's helper does:
// a refusal is refused, a deadline is a timeout, an unreachable network or host
// is unreachable, and anything else is an error. Only a timeout passes a
// must-block target, so a doubtful error is never read as one.
func classifyEgressError(err error) string {
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return vmpalEgressRefused
	case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTUNREACH):
		return vmpalEgressUnreachable
	case errors.Is(err, syscall.ETIMEDOUT), errors.Is(err, os.ErrDeadlineExceeded), errors.Is(err, context.DeadlineExceeded):
		return vmpalEgressTimeout
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return vmpalEgressTimeout
	}
	return vmpalEgressError
}
