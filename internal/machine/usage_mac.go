package machine

import (
	"context"
	"encoding/binary"
	"math"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// What a Mac can say about itself without cgo. The binary is static and built
// with CGO_ENABLED=0, which rules out the Mach host_statistics calls every
// native tool uses, so each figure comes from the nearest thing pure Go can
// reach:
//
//   - the one-minute load average from the vm.loadavg sysctl, read directly;
//   - available memory from the kernel's page counters, also sysctls: free
//     pages plus the file-backed and purgeable ones, which the system gives
//     back under pressure, so the figure is Linux's MemAvailable in spirit and
//     not the "free" a Mac always shows near zero;
//   - CPU busy time from a bounded run of /usr/bin/top, because macOS keeps its
//     per-CPU tick counters behind the Mach interface and exposes no sysctl for
//     them (there is no kern.cp_time here). top is the stock tool that reads
//     them, and its second sample is a share over an interval.
//
// I/O wait and steal have no counterpart on macOS, so they are never reported:
// absent, which is not the same as zero.

const (
	// macCPUWindow is how long top watches before it prints the sample that
	// counts. Its first sample is an average since boot, which says nothing about
	// now, so the figure is read from the second.
	macCPUWindow = 5 * time.Second
	// macCPUEvery is the gap between one run's start and the next. A run holds a
	// process for the window, so this keeps the cost of measuring well under the
	// work being measured.
	macCPUEvery = 10 * time.Second
	// macCPUMaxAge is how long a reading stands once nothing has replaced it. A
	// probe that has started failing must not leave its last good figure on a
	// host for ever: the controller treats an old sample as no sample, and so
	// does this.
	macCPUMaxAge = 60 * time.Second
	// macCPUTimeout bounds one run, which is the window plus start-up on a
	// machine that may be hard pressed, the very case being measured.
	macCPUTimeout = 30 * time.Second
	// macPageLimit rejects a page count no machine has, so a counter read at the
	// wrong width cannot become an enormous amount of free memory.
	macPageLimit = 1 << 40
)

// macSource is a Mac's side of UsageSampler: what it reads instead of procfs.
// Both seams are injected so the arithmetic is tested on Linux, where there is
// no sysctl and no top.
type macSource struct {
	// cpus is how many logical CPUs this machine has, the figure a caller's CPU
	// count has to match before a whole-machine reading is attributed to it.
	cpus   int
	sysctl func(name string) ([]byte, error)
	cpu    *macCPUProbe
}

func newMacSource(cpus int, sysctl func(string) ([]byte, error), run func(context.Context) (string, error)) *macSource {
	return &macSource{cpus: cpus, sysctl: sysctl, cpu: &macCPUProbe{run: run, now: time.Now, spawn: func(f func()) { go f() }}}
}

// sample answers as UsageSampler.Sample does on Linux, and for the same
// reason refuses to answer for a machine other than the one the caller means:
// a Docker Desktop daemon reports its VM's size, and this machine's load says
// nothing about that.
func (m *macSource) sample(cpus int, memoryMB int64) Usage {
	var out Usage
	if cpus > 0 && cpus == m.cpus {
		if v, ok := m.cpu.Latest(); ok {
			out.CPUPercent = &v
		}
		if raw, err := m.sysctl("vm.loadavg"); err == nil {
			if v, ok := macLoadAverage(raw); ok {
				out.LoadAverage1 = &v
			}
		}
	}
	if total, ok := m.totalMB(); ok && total == memoryMB {
		if available, ok := m.availableMB(); ok && available <= total {
			out.MemoryAvailableMB = &available
		}
	}
	return out
}

// sysctlInt reads an integer sysctl at whatever width the kernel gives it. The
// page counters are four bytes on one release and eight on another, and a read
// at the wrong width fails outright, so the width is taken from what came back.
func (m *macSource) sysctlInt(name string) (uint64, bool) {
	raw, err := m.sysctl(name)
	if err != nil {
		return 0, false
	}
	switch len(raw) {
	case 4:
		return uint64(binary.NativeEndian.Uint32(raw)), true
	case 8:
		return binary.NativeEndian.Uint64(raw), true
	}
	return 0, false
}

func (m *macSource) totalMB() (int64, bool) {
	v, ok := m.sysctlInt("hw.memsize")
	if !ok || v < 1<<20 || v > math.MaxInt64 {
		return 0, false
	}
	return int64(v >> 20), true
}

// availableMB is the memory the system would hand out without swapping: free
// pages, the file-backed pages (the cache, which the kernel drops first) and
// the purgeable ones (which apps have marked as recomputable). Speculative
// pages are already in the file-backed count. Every counter has to be read: a
// missing one would understate what is free, and a host that looks full is
// held back from work it could take.
func (m *macSource) availableMB() (int64, bool) {
	size, ok := m.sysctlInt("hw.pagesize")
	if !ok || size == 0 || size > 1<<20 {
		return 0, false
	}
	var pages uint64
	for _, name := range []string{"vm.page_free_count", "vm.page_pageable_external_count", "vm.page_purgeable_count"} {
		v, ok := m.sysctlInt(name)
		if !ok || v > macPageLimit {
			return 0, false
		}
		pages += v
	}
	return int64(pages * size >> 20), true
}

// macLoadAverage reads the one-minute figure from the raw vm.loadavg value, a C
// struct of three fixed-point averages (four bytes each, then padding to eight)
// and the long that is their divisor.
func macLoadAverage(raw []byte) (float64, bool) {
	if len(raw) < 24 {
		return 0, false
	}
	scale := binary.NativeEndian.Uint64(raw[16:24])
	if scale == 0 {
		return 0, false
	}
	return float64(binary.NativeEndian.Uint32(raw[0:4])) / float64(scale), true
}

// parseTopCPUBusy reads how busy the machine was from the output of a two-sample
// top run: the idle share of the last "CPU usage:" line, taken from 100. A run
// that printed only one sample is refused, because that one is the average since
// boot and would report a host that has been quiet for a week as quiet now.
func parseTopCPUBusy(out string) (float64, bool) {
	var last string
	samples := 0
	for _, line := range strings.Split(out, "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "CPU usage:"); ok {
			last = rest
			samples++
		}
	}
	if samples < 2 {
		return 0, false
	}
	for _, part := range strings.Split(last, ",") {
		fields := strings.Fields(part)
		if len(fields) != 2 || fields[1] != "idle" || !strings.HasSuffix(fields[0], "%") {
			continue
		}
		idle, err := strconv.ParseFloat(strings.TrimSuffix(fields[0], "%"), 64)
		if err != nil || math.IsNaN(idle) || idle < 0 || idle > 100 {
			return 0, false
		}
		return 100 - idle, true
	}
	return 0, false
}

// macCPUProbe keeps the last CPU reading from top and starts the next in the
// background. Sampling has to stay free of waiting, because it is called from
// the heartbeat and from a controller's housekeeping tick, and top needs its
// whole window to say anything: so a call returns what the last finished run
// found and, at most once in macCPUEvery, starts another.
type macCPUProbe struct {
	mu sync.Mutex
	// run, now and spawn are seams: a test supplies top's output, the time, and
	// a way to run the refresh when it chooses.
	run       func(context.Context) (string, error)
	now       func() time.Time
	spawn     func(func())
	busy      float64
	at        time.Time
	have      bool
	running   bool
	startedAt time.Time
}

// Latest is the last reading and whether it still stands. The first call has
// none, as the first Linux sample has no delta to take a share of.
func (p *macCPUProbe) Latest() (float64, bool) {
	p.mu.Lock()
	now := p.now()
	busy, ok := p.busy, p.have && now.Sub(p.at) <= macCPUMaxAge
	start := !p.running && (p.startedAt.IsZero() || now.Sub(p.startedAt) >= macCPUEvery)
	if start {
		p.running, p.startedAt = true, now
	}
	p.mu.Unlock()
	if start {
		p.spawn(p.refresh)
	}
	return busy, ok
}

func (p *macCPUProbe) refresh() {
	ctx, cancel := context.WithTimeout(context.Background(), macCPUTimeout)
	defer cancel()
	out, err := p.run(ctx)
	var busy float64
	ok := false
	if err == nil {
		busy, ok = parseTopCPUBusy(out)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.running = false
	p.busy, p.at, p.have = busy, p.now(), ok
}

// runTop runs the stock top for two samples, one window apart, with nothing
// from the agent's environment and a locale that writes decimals with a point.
func runTop(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, "/usr/bin/top", "-l", "2", "-s", strconv.Itoa(int(macCPUWindow/time.Second)), "-n", "0")
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL=C"}
	cmd.Dir = "/"
	cmd.WaitDelay = 2 * time.Second
	out, err := cmd.Output()
	return string(out), err
}
