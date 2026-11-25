package backend

// The firewall. Zoomies edits pf in one place only: its own anchor, whose rules
// match only its own users. Until now it checked a host's firewall and never
// wrote one; in this mode a job's network is the one thing the agent has to be
// able to prove, and a policy somebody else maintains cannot be proved from here.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// jobUserBlockedV4 is the private ranges a job may not reach over IPv4: the LAN,
// the tailnet (100.64.0.0/10) and link-local addresses. IPv6 has no such list,
// because on a dual-stack LAN every other host has a global address as well, which
// no list of private ranges would cover: a job user gets no IPv6 beyond loopback,
// and keeps the IPv4 internet.
const jobUserBlockedV4 = "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, 169.254.0.0/16"

var pfInterfaceName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*$`)

// renderJobUserAnchor is the text of the anchor. The second blocks all IPv6 but
// ::1, so that a job can still reach its own servers on loopback. The third rule
// blocks the host's
// own addresses on every interface but loopback, written as (name) so that pf
// follows an address that changes, because a job that could reach the host's
// public address would reach its services as the host. Loopback stays open: a
// job runs and tests its own servers there. Blocking "to self" would take that
// away, and "on ! lo0" does not block the public address at all, because the
// host's traffic to itself goes over lo0.
func renderJobUserAnchor(users []string, ifaces []jobUserIface) string {
	who := "user { " + strings.Join(users, ", ") + " }"
	var names []string
	for _, i := range ifaces {
		if i.Name != "lo0" && i.HasAddr && pfInterfaceName.MatchString(i.Name) {
			names = append(names, "("+i.Name+")")
		}
	}
	sort.Strings(names)
	var b strings.Builder
	fmt.Fprintf(&b, "block drop out quick inet from any to { %s } %s\n", jobUserBlockedV4, who)
	fmt.Fprintf(&b, "block drop out quick inet6 from any to ! ::1 %s\n", who)
	if len(names) > 0 {
		fmt.Fprintf(&b, "block drop out quick from any to { %s } %s\n", strings.Join(names, ", "), who)
	}
	return b.String()
}

// jobUserPF loads and watches the anchor.
type jobUserPF struct {
	u  *jobUsers
	mu sync.Mutex
	// rendered is the text last loaded and baseline what pf read back for it.
	// pf normalises what it is given, so the comparison is between pf's own
	// text on both sides and never against what Zoomies wrote.
	rendered string
	baseline string
}

var pfToken = regexp.MustCompile(`Token\s*:\s*([0-9]+)`)

func (p *jobUserPF) text() (string, error) {
	ifaces, err := p.u.sys.Interfaces()
	if err != nil {
		return "", fmt.Errorf("listing the network interfaces: %w", err)
	}
	// Every account that exists, and not only those offered to new jobs: a job
	// that survived a restart can be running as one the capacity no longer offers,
	// and it needs the same rules.
	var users []string
	for _, s := range p.u.covered() {
		users = append(users, s.name)
	}
	return renderJobUserAnchor(users, ifaces), nil
}

func (p *jobUserPF) tokenPath() string    { return filepath.Join(p.u.stateDir, "pf.token") }
func (p *jobUserPF) baselinePath() string { return filepath.Join(p.u.stateDir, "pf.baseline") }

// load writes the anchor, turns pf on and records what pf says it now holds.
func (p *jobUserPF) load(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.loadLocked(ctx)
}

func (p *jobUserPF) loadLocked(ctx context.Context) error {
	text, err := p.text()
	if err != nil {
		return err
	}
	if _, err := p.u.runCmd(ctx, jobUserCommand{Argv: []string{"/sbin/pfctl", "-a", jobUserAnchor, "-f", "-"}, Stdin: text}); err != nil {
		return fmt.Errorf("loading the anchor %s: %w", jobUserAnchor, err)
	}
	if err := p.enable(ctx); err != nil {
		return err
	}
	rules, err := p.u.run(ctx, "/sbin/pfctl", "-a", jobUserAnchor, "-sr")
	if err != nil {
		return fmt.Errorf("reading the anchor back: %w", err)
	}
	rules = strings.TrimSpace(rules)
	if rules == "" {
		return fmt.Errorf("the anchor %s reads back empty after it was loaded", jobUserAnchor)
	}
	p.rendered, p.baseline = text, rules
	if err := writeFileAtomic(p.baselinePath(), []byte(rules+"\n"), 0o600); err != nil {
		p.u.log.Warn("could not save the firewall baseline", "error", err)
	}
	return nil
}

// enable turns pf on and keeps the one reference it gives. The one an earlier
// run of the agent took is released, so restarts do not pile references up and
// keep pf on after the agent is uninstalled, but only once the new one is taken
// and written down: released first, pf would be off between the two whenever the
// old reference was the only one, and the firewall would be down in that gap.
func (p *jobUserPF) enable(ctx context.Context) error {
	old := ""
	if b, err := os.ReadFile(p.tokenPath()); err == nil {
		if tok := strings.TrimSpace(string(b)); tok != "" {
			if _, err := strconv.Atoi(tok); err == nil {
				old = tok
			}
		}
	}
	res, err := p.u.sys.Run(ctx, jobUserCommand{Argv: []string{"/sbin/pfctl", "-E"}})
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("pfctl -E exited %d: %s", res.ExitCode, strings.TrimSpace(res.Output))
	}
	m := pfToken.FindStringSubmatch(res.Output)
	if m == nil {
		return fmt.Errorf("pfctl -E gave no token, so pf's reference could not be kept: %s", strings.TrimSpace(res.Output))
	}
	record := p.u.sys.MkdirAll(p.u.stateDir, 0o700)
	if record == nil {
		record = writeFileAtomic(p.tokenPath(), []byte(m[1]+"\n"), 0o600)
	}
	if record != nil {
		// A reference nobody wrote down could never be released, so it is given
		// back at once, and the old one, which is written down, stays.
		_, _ = p.u.sys.Run(ctx, jobUserCommand{Argv: []string{"/sbin/pfctl", "-X", m[1]}})
		return record
	}
	if old != "" && old != m[1] {
		if _, err := p.u.run(ctx, "/sbin/pfctl", "-X", old); err != nil {
			p.u.log.Warn("could not release the firewall reference an earlier run of the agent took", "error", err)
		}
	}
	return nil
}

// errJobUserAnchorChanged is the anchor not being what was loaded.
var errJobUserAnchorChanged = errors.New("the firewall anchor is not what Zoomies loaded")

// verify compares pf with what Zoomies loaded. When the interfaces have changed
// it renders again and reloads, which is not an incident; when the anchor is
// missing, different or pf is off, it is.
func (p *jobUserPF) verify(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.rendered == "" {
		return fmt.Errorf("%w: it was never loaded", errJobUserAnchorChanged)
	}
	text, err := p.text()
	if err != nil {
		return err
	}
	if text != p.rendered {
		p.u.log.Info("the network interfaces changed, so the firewall anchor is being rendered again")
		return p.loadLocked(ctx)
	}
	info, err := p.u.run(ctx, "/sbin/pfctl", "-s", "info")
	if err != nil {
		return fmt.Errorf("%w: asking pf whether it is on: %v", errJobUserAnchorChanged, err)
	}
	if !strings.Contains(info, "Status: Enabled") {
		return fmt.Errorf("%w: pf is switched off", errJobUserAnchorChanged)
	}
	rules, err := p.u.run(ctx, "/sbin/pfctl", "-a", jobUserAnchor, "-sr")
	if err != nil {
		return fmt.Errorf("%w: reading it: %v", errJobUserAnchorChanged, err)
	}
	if strings.TrimSpace(rules) != p.baseline {
		return fmt.Errorf("%w: it holds %q now", errJobUserAnchorChanged, jobUserFirstLine(strings.TrimSpace(rules)))
	}
	return nil
}
