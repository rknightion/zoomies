package machine

import (
	"context"
	"encoding/binary"
	"errors"
	"testing"
	"time"
)

func sysctlWidth4(v uint32) []byte {
	b := make([]byte, 4)
	binary.NativeEndian.PutUint32(b, v)
	return b
}

func sysctlWidth8(v uint64) []byte {
	b := make([]byte, 8)
	binary.NativeEndian.PutUint64(b, v)
	return b
}

// loadavgStruct lays out the C struct the kernel returns for vm.loadavg: three
// four-byte averages, four bytes of padding, then the eight-byte divisor.
func loadavgStruct(one uint32, scale uint64) []byte {
	b := make([]byte, 24)
	binary.NativeEndian.PutUint32(b[0:4], one)
	binary.NativeEndian.PutUint64(b[16:24], scale)
	return b
}

func fakeSysctl(values map[string][]byte) func(string) ([]byte, error) {
	return func(name string) ([]byte, error) {
		if v, ok := values[name]; ok {
			return v, nil
		}
		return nil, errors.New("unknown oid " + name)
	}
}

// A sixteen gibibyte Mac with 16 KiB pages and 350000 of them reclaimable.
func macSysctls() map[string][]byte {
	return map[string][]byte{
		"hw.memsize":                      sysctlWidth8(16 << 30),
		"hw.pagesize":                     sysctlWidth8(16384),
		"vm.page_free_count":              sysctlWidth4(100000),
		"vm.page_pageable_external_count": sysctlWidth4(200000),
		"vm.page_purgeable_count":         sysctlWidth4(50000),
		"vm.loadavg":                      loadavgStruct(3072, 2048),
	}
}

const topTwoSamples = `Processes: 400 total, 3 running, 397 sleeping, 2000 threads
2026/11/25 20:00:00
Load Avg: 1.50, 1.20, 1.10
CPU usage: 2.00% user, 3.00% sys, 95.00% idle
SharedLibs: 600M resident, 100M data, 50M linkedit.
PhysMem: 12G used (2G wired, 1G compressor), 4G unused.

Processes: 400 total, 3 running, 397 sleeping, 2000 threads
2026/11/25 20:00:05
Load Avg: 1.60, 1.21, 1.10
CPU usage: 10.00% user, 15.00% sys, 75.00% idle
SharedLibs: 600M resident, 100M data, 50M linkedit.
`

func TestTopCPUReadsTheSecondSampleBecauseTheFirstIsAnAverageSinceBoot(t *testing.T) {
	got, ok := parseTopCPUBusy(topTwoSamples)
	if !ok || got != 25 {
		t.Fatalf("busy = %v, %v; want 25 from the idle share of the last sample", got, ok)
	}
}

func TestTopCPURefusesWhatItCannotTrust(t *testing.T) {
	oneSample := "Load Avg: 1.50, 1.20, 1.10\nCPU usage: 2.00% user, 3.00% sys, 95.00% idle\n"
	for name, raw := range map[string]string{
		"nothing":        "",
		"one sample":     oneSample,
		"no idle column": oneSample + "CPU usage: 2.00% user, 3.00% sys\n",
		"not a number":   oneSample + "CPU usage: 2.00% user, 3.00% sys, many% idle\n",
		"over a hundred": oneSample + "CPU usage: 0.00% user, 0.00% sys, 140.00% idle\n",
		"negative idle":  oneSample + "CPU usage: 0.00% user, 0.00% sys, -3.00% idle\n",
	} {
		if v, ok := parseTopCPUBusy(raw); ok {
			t.Errorf("%s: accepted, read %v", name, v)
		}
	}
	if v, ok := parseTopCPUBusy(oneSample + "CPU usage: 0.00% user, 0.00% sys, 100.00% idle\n"); !ok || v != 0 {
		t.Fatalf("a measured idle machine was rejected: %v %v", v, ok)
	}
}

func TestMacLoadAverageIsTheFirstFixedPointFigureOverTheDivisor(t *testing.T) {
	if v, ok := macLoadAverage(loadavgStruct(3072, 2048)); !ok || v != 1.5 {
		t.Fatalf("load = %v, %v; want 1.5", v, ok)
	}
	// Zero load is a measurement, and the one that must not be what an unread
	// struct turns into.
	if v, ok := macLoadAverage(loadavgStruct(0, 2048)); !ok || v != 0 {
		t.Fatalf("idle load = %v, %v", v, ok)
	}
	for name, raw := range map[string][]byte{"empty": nil, "short": make([]byte, 16), "no divisor": loadavgStruct(3072, 0)} {
		if v, ok := macLoadAverage(raw); ok {
			t.Errorf("%s: accepted, read %v", name, v)
		}
	}
}

func TestMacAvailableMemoryCountsFreeCachedAndPurgeablePagesAtWhateverWidthTheKernelGives(t *testing.T) {
	m := newMacSource(8, fakeSysctl(macSysctls()), nil)
	// (100000 + 200000 + 50000) pages of 16 KiB, in mebibytes.
	if got, ok := m.availableMB(); !ok || got != 5468 {
		t.Fatalf("available = %v, %v; want 5468", got, ok)
	}
	// One release answers the purgeable count with eight bytes, and a reader
	// that insisted on four would lose the whole figure.
	wide := macSysctls()
	wide["vm.page_purgeable_count"] = sysctlWidth8(50000)
	if got, ok := newMacSource(8, fakeSysctl(wide), nil).availableMB(); !ok || got != 5468 {
		t.Fatalf("eight-byte counter: available = %v, %v; want 5468", got, ok)
	}
}

func TestMacAvailableMemoryIsUnmeasuredWhenAnyCounterIsMissingOrImpossible(t *testing.T) {
	for _, drop := range []string{"hw.pagesize", "vm.page_free_count", "vm.page_pageable_external_count", "vm.page_purgeable_count"} {
		values := macSysctls()
		delete(values, drop)
		if v, ok := newMacSource(8, fakeSysctl(values), nil).availableMB(); ok {
			t.Errorf("without %s: reported %v", drop, v)
		}
	}
	values := macSysctls()
	values["vm.page_free_count"] = []byte{1, 2, 3}
	if v, ok := newMacSource(8, fakeSysctl(values), nil).availableMB(); ok {
		t.Errorf("a counter of three bytes was read as %v", v)
	}
	values = macSysctls()
	values["vm.page_free_count"] = sysctlWidth8(1 << 50)
	if v, ok := newMacSource(8, fakeSysctl(values), nil).availableMB(); ok {
		t.Errorf("a page count no machine has was read as %v", v)
	}
}

// A rig that lets a test decide when top finishes: the refresh is queued, not
// run, so the sample it would have fed is seen before and after.
type macProbeRig struct {
	probe  *macCPUProbe
	now    time.Time
	output string
	err    error
	runs   int
	queued []func()
}

func newMacProbeRig() *macProbeRig {
	r := &macProbeRig{now: time.Date(2026, 11, 25, 20, 0, 0, 0, time.UTC), output: topTwoSamples}
	r.probe = &macCPUProbe{
		run:   func(context.Context) (string, error) { r.runs++; return r.output, r.err },
		now:   func() time.Time { return r.now },
		spawn: func(f func()) { r.queued = append(r.queued, f) },
	}
	return r
}

func (r *macProbeRig) finish() {
	for _, f := range r.queued {
		f()
	}
	r.queued = nil
}

func TestMacCPUReadingArrivesAfterTheFirstRunFinishesAndNeverBlocksTheCaller(t *testing.T) {
	r := newMacProbeRig()
	if _, ok := r.probe.Latest(); ok {
		t.Fatal("the first call had a reading before any run had finished")
	}
	if r.runs != 0 || len(r.queued) != 1 {
		t.Fatalf("the first call must queue a run and not wait for it: runs=%d queued=%d", r.runs, len(r.queued))
	}
	r.finish()
	r.now = r.now.Add(time.Second)
	if v, ok := r.probe.Latest(); !ok || v != 25 {
		t.Fatalf("after the run: %v, %v; want 25", v, ok)
	}
}

func TestMacCPUProbeNeverRunsTwoTopsAtOnce(t *testing.T) {
	r := newMacProbeRig()
	r.probe.Latest()
	// Long past the gap, but the first run has not come back: a second process
	// beside it would double the cost of measuring a machine that may be
	// struggling.
	r.now = r.now.Add(macCPUEvery + time.Second)
	r.probe.Latest()
	if len(r.queued) != 1 {
		t.Fatalf("a run was started while another was in flight: %d queued", len(r.queued))
	}
}

func TestMacCPUProbeStartsAtMostOneRunInTheGap(t *testing.T) {
	r := newMacProbeRig()
	r.probe.Latest()
	r.finish()
	r.now = r.now.Add(2 * time.Second)
	r.probe.Latest()
	if len(r.queued) != 0 {
		t.Fatal("a run was started inside the gap since the last one")
	}
	r.now = r.now.Add(macCPUEvery)
	r.probe.Latest()
	if len(r.queued) != 1 {
		t.Fatalf("no run was started once the gap had passed: %d queued", len(r.queued))
	}
}

func TestMacCPUReadingIsDroppedWhenTheProbeFailsOrGoesStale(t *testing.T) {
	r := newMacProbeRig()
	r.probe.Latest()
	r.finish()
	if _, ok := r.probe.Latest(); !ok {
		t.Fatal("no reading after a good run")
	}
	// A reading nothing has replaced stops standing: the controller would not
	// trust a sample that old, and a probe that has gone quiet must not keep a
	// host looking measured.
	r.now = r.now.Add(macCPUMaxAge + time.Second)
	if _, ok := r.probe.Latest(); ok {
		t.Fatal("a stale reading still stood")
	}
	r = newMacProbeRig()
	r.probe.Latest()
	r.finish()
	r.now = r.now.Add(macCPUEvery)
	r.err = errors.New("top: not found")
	r.probe.Latest()
	r.finish()
	if v, ok := r.probe.Latest(); ok {
		t.Fatalf("a failed run left the earlier reading standing: %v", v)
	}
	r.err, r.output = nil, "Processes: 1 total\n"
	r.now = r.now.Add(macCPUEvery)
	r.probe.Latest()
	r.finish()
	if v, ok := r.probe.Latest(); ok {
		t.Fatalf("output with no CPU line became a reading: %v", v)
	}
}

func inlineMacSource(values map[string][]byte, cpus int, r *macProbeRig) *macSource {
	m := newMacSource(cpus, fakeSysctl(values), nil)
	m.cpu = r.probe
	r.probe.spawn = func(f func()) { f() }
	return m
}

func TestMacSampleReportsCPULoadAndAvailableMemoryAndNeverIOWaitOrSteal(t *testing.T) {
	r := newMacProbeRig()
	s := UsageSampler{mac: inlineMacSource(macSysctls(), 8, r)}
	first := s.Sample(8, 16384)
	if first.CPUPercent != nil {
		t.Fatalf("the first sample has no finished run to read: %v", *first.CPUPercent)
	}
	if first.LoadAverage1 == nil || *first.LoadAverage1 != 1.5 {
		t.Fatalf("load = %v, want 1.5", first.LoadAverage1)
	}
	if first.MemoryAvailableMB == nil || *first.MemoryAvailableMB != 5468 {
		t.Fatalf("available memory = %v, want 5468", first.MemoryAvailableMB)
	}
	second := s.Sample(8, 16384)
	if second.CPUPercent == nil || *second.CPUPercent != 25 {
		t.Fatalf("CPU = %v, want 25", second.CPUPercent)
	}
	// macOS has neither counter. Absent is the honest answer, where a zero
	// would say a Mac had measured no starvation.
	if second.IOWaitPercent != nil || second.StealPercent != nil {
		t.Fatalf("I/O wait or steal reported on a Mac: %+v", second)
	}
}

func TestMacSampleDoesNotAttributeThisMachineToAnotherOfADifferentSize(t *testing.T) {
	r := newMacProbeRig()
	s := UsageSampler{mac: inlineMacSource(macSysctls(), 8, r)}
	// Docker Desktop reports its VM's size, not the Mac's.
	for _, c := range []struct {
		cpus     int
		memoryMB int64
	}{{4, 8192}, {0, 0}} {
		got := s.Sample(c.cpus, c.memoryMB)
		if got.CPUPercent != nil || got.LoadAverage1 != nil || got.MemoryAvailableMB != nil {
			t.Fatalf("the Mac's figures were attributed to a %d CPU, %d MB machine: %+v", c.cpus, c.memoryMB, got)
		}
	}
	if r.runs != 0 || len(r.queued) != 0 {
		t.Fatalf("top was run to measure a machine whose figures would be thrown away: runs=%d", r.runs)
	}
	// CPU count and memory are judged separately, as on Linux.
	if got := s.Sample(8, 8192); got.MemoryAvailableMB != nil || got.LoadAverage1 == nil {
		t.Fatalf("a matching CPU count with a different memory size: %+v", got)
	}
}

func TestMacSampleDropsAvailableMemoryThatExceedsTheMachine(t *testing.T) {
	values := macSysctls()
	values["vm.page_free_count"] = sysctlWidth4(900000)
	r := newMacProbeRig()
	s := UsageSampler{mac: inlineMacSource(values, 8, r)}
	if got := s.Sample(8, 16384); got.MemoryAvailableMB != nil {
		t.Fatalf("more available memory than the machine has: %v", *got.MemoryAvailableMB)
	}
}

func TestMacSampleWithNoSysctlsReportsNothingRatherThanIdle(t *testing.T) {
	r := newMacProbeRig()
	s := UsageSampler{mac: inlineMacSource(map[string][]byte{}, 8, r)}
	if got := s.Sample(8, 16384); got.LoadAverage1 != nil || got.MemoryAvailableMB != nil {
		t.Fatalf("unreadable sysctls became a reading: %+v", got)
	}
}
