//go:build darwin

package machine

import (
	"context"
	"runtime"
	"testing"
)

// These run on a real Mac, the only place the sysctl names and the shape of
// top's output can be checked. The cross-platform tests hold the arithmetic;
// this holds the assumptions it rests on.
func TestARealMacAnswersEverySysctlTheSamplerReads(t *testing.T) {
	m := defaultMacSource()
	if m == nil {
		t.Fatal("no source on darwin")
	}
	total, ok := m.totalMB()
	if !ok || total <= 0 {
		t.Fatalf("hw.memsize unreadable: %v %v", total, ok)
	}
	available, ok := m.availableMB()
	if !ok || available <= 0 || available > total {
		t.Fatalf("available memory = %v of %v, %v", available, total, ok)
	}
	raw, err := m.sysctl("vm.loadavg")
	if err != nil {
		t.Fatal(err)
	}
	if load, ok := macLoadAverage(raw); !ok || load < 0 {
		t.Fatalf("vm.loadavg (%d bytes) read as %v, %v", len(raw), load, ok)
	}
	got := m.sample(runtime.NumCPU(), total)
	if got.LoadAverage1 == nil || got.MemoryAvailableMB == nil {
		t.Fatalf("a sample of this Mac missed a figure: %+v", got)
	}
	if got.IOWaitPercent != nil || got.StealPercent != nil {
		t.Fatalf("I/O wait or steal reported on a Mac: %+v", got)
	}
}

func TestTheStockTopStillPrintsASecondCPUUsageLine(t *testing.T) {
	if testing.Short() {
		t.Skip("top takes its whole window to answer")
	}
	out, err := runTop(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if busy, ok := parseTopCPUBusy(out); !ok || busy < 0 || busy > 100 {
		t.Fatalf("top's output gave %v, %v:\n%s", busy, ok, out)
	}
}
