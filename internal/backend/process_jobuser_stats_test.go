package backend

import (
	"context"
	"errors"
	"math"
	"path/filepath"
	"testing"
)

// A job-user host has no container to ask, and a Mac has no /proc, so what a
// job is using is whatever its account is running. Each job runs entirely as
// its slot's UID, which is what makes the sum over that UID the job's usage.
func TestJobUserStatsAddsUpEverythingTheJobsAccountIsRunning(t *testing.T) {
	const kib = 1024
	for _, tc := range []struct {
		name    string
		procs   func(uid, neighbour int) []jobUserProc
		wantCPU float64
		wantMem int64
	}{
		{
			name: "every process of the account is counted, whether its real or its effective user is the slot",
			procs: func(uid, neighbour int) []jobUserProc {
				return []jobUserProc{
					{PID: 10, RUID: uid, EUID: uid, CPUPercent: 10.5, RSSBytes: 1000 * kib},
					{PID: 11, RUID: 0, EUID: uid, CPUPercent: 20, RSSBytes: 2000 * kib},
					{PID: 12, RUID: uid, EUID: 0, CPUPercent: 150, RSSBytes: 4000 * kib},
				}
			},
			wantCPU: 180.5,
			wantMem: 7000 * kib,
		},
		{
			name: "a neighbouring slot's processes and the system's are not the job's",
			procs: func(uid, neighbour int) []jobUserProc {
				return []jobUserProc{
					{PID: 1, RUID: 0, EUID: 0, CPUPercent: 50, RSSBytes: 9000 * kib},
					{PID: 10, RUID: uid, EUID: uid, CPUPercent: 5, RSSBytes: 100 * kib},
					{PID: 20, RUID: neighbour, EUID: neighbour, CPUPercent: 99, RSSBytes: 8000 * kib},
				}
			},
			wantCPU: 5,
			wantMem: 100 * kib,
		},
		{
			name:  "an account running nothing reports nothing",
			procs: func(uid, neighbour int) []jobUserProc { return nil },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := startedJobUserFixture(t, 2)
			a := jobUserCreate(t, x, "runner-a")
			bb := jobUserCreate(t, x, "runner-b")
			own := x.u.slotNamed(slotOf(t, a)).uid
			neighbour := x.u.slotNamed(slotOf(t, bb)).uid
			x.f.procs = tc.procs(own, neighbour)

			got, err := x.b.Stats(context.Background(), a)
			if err != nil {
				t.Fatalf("Stats: %v", err)
			}
			if math.Abs(got.CPUPercent-tc.wantCPU) > 0.001 || got.MemoryBytes != tc.wantMem {
				t.Errorf("Stats = cpu %v, memory %d; want cpu %v, memory %d", got.CPUPercent, got.MemoryBytes, tc.wantCPU, tc.wantMem)
			}
		})
	}
}

// The agent stamps the time when it stores a sample, but a sample that carries
// its own says when the figures were true, which is what a reader of one
// sample on its own needs.
func TestJobUserStatsSaysWhenItSampled(t *testing.T) {
	x := startedJobUserFixture(t, 1)
	h := jobUserCreate(t, x, "runner-a")
	x.f.procs = []jobUserProc{{PID: 10, RUID: 651, EUID: 651, CPUPercent: 1, RSSBytes: 4096}}

	got, err := x.b.Stats(context.Background(), h)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if got.SampledAt == nil || !got.SampledAt.Equal(x.f.now()) {
		t.Errorf("SampledAt = %v, want %v", got.SampledAt, x.f.now())
	}
}

// Stats is best effort: the agent keeps the sample it had, and a heartbeat
// must never fail, for a slot that is gone, a runner nobody holds a slot for or
// a ps that would not run.
func TestJobUserStatsReportsNothingRatherThanFailing(t *testing.T) {
	for _, tc := range []struct {
		name   string
		handle func(t *testing.T, x *jobUserFixture, h Handle) Handle
		prep   func(x *jobUserFixture)
	}{
		{
			name:   "ps cannot be run",
			handle: func(_ *testing.T, _ *jobUserFixture, h Handle) Handle { return h },
			prep:   func(x *jobUserFixture) { x.f.procsErr = errors.New("could not run /bin/ps") },
		},
		{
			name: "no slot is held by the runner directory",
			handle: func(_ *testing.T, x *jobUserFixture, _ Handle) Handle {
				return Handle(filepath.Join(x.root, "runners", "nowhere"))
			},
		},
		{
			name: "the runner's slot has been given back",
			handle: func(t *testing.T, x *jobUserFixture, h Handle) Handle {
				if err := x.b.Remove(context.Background(), h); err != nil {
					t.Fatalf("Remove: %v", err)
				}
				return h
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := startedJobUserFixture(t, 1)
			h := jobUserCreate(t, x, "runner-a")
			x.f.procs = []jobUserProc{{PID: 10, RUID: 651, EUID: 651, CPUPercent: 40, RSSBytes: 1 << 20}}
			h = tc.handle(t, x, h)
			if tc.prep != nil {
				tc.prep(x)
			}

			got, err := x.b.Stats(context.Background(), h)
			if err != nil {
				t.Fatalf("Stats = %v, want no error", err)
			}
			if got.CPUPercent != 0 || got.MemoryBytes != 0 || got.SampledAt != nil {
				t.Errorf("Stats = %+v, want nothing", got)
			}
		})
	}
}

// After an agent restart the slot a runner holds is rebuilt from its record, and
// a job that is still running must keep being measured.
func TestJobUserStatsFindsTheSlotOfARunnerAnEarlierAgentStarted(t *testing.T) {
	x := startedJobUserFixture(t, 2)
	h := jobUserCreate(t, x, "runner-a")
	uid := x.u.slotNamed(slotOf(t, h)).uid
	x.f.procs = []jobUserProc{{PID: 10, RUID: uid, EUID: uid, CPUPercent: 12, RSSBytes: 3 << 20}}

	y := x.restart(t, 2)
	if err := y.b.StartJobUsers(context.Background()); err != nil {
		t.Fatalf("StartJobUsers: %v", err)
	}
	got, err := y.b.Stats(context.Background(), h)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if got.CPUPercent != 12 || got.MemoryBytes != 3<<20 {
		t.Errorf("Stats = %+v, want cpu 12 and 3 MiB", got)
	}
}
