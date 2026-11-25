package backend

import (
	"fmt"
	"sort"
	"strings"
)

// jobUserPath is the runner's PATH: the system folders, then Homebrew's. Homebrew
// goes last so that nothing in it can shadow the Xcode toolchain. It is the
// recipe the VM guest's helper uses (vmpal_guest.sh), and a test reads that
// script so the two cannot drift.
const jobUserPath = "/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/opt/homebrew/bin:/opt/homebrew/sbin"

// jobUserLocale is what LANG and LC_ALL default to, as in the VM guest.
const jobUserLocale = "en_US.UTF-8"

// checkJobUserEnv refuses a pool environment the job-user launcher cannot pass on
// as written. The runner's own registration is Zoomies's, so a pool may not set
// it, and a name the shell could not export would be dropped without a word.
func checkJobUserEnv(spec Spec) error {
	for name := range spec.Env {
		switch {
		case !vmpalEnvName.MatchString(name):
			return fmt.Errorf("%w: pool %q sets an environment variable named %q, which is not a valid name; rename it", ErrBackendConfig, spec.PoolName, name)
		case name == EnvUpstreamJITConfig || name == EnvJITConfig:
			return fmt.Errorf("%w: pool %q sets %s, which Zoomies keeps for the runner's registration; remove it from the pool", ErrBackendConfig, spec.PoolName, name)
		case strings.ContainsRune(spec.Env[name], 0):
			return fmt.Errorf("%w: pool %q sets %s to a value with a NUL byte in it, which no process environment can hold", ErrBackendConfig, spec.PoolName, name)
		}
	}
	return nil
}

// jobUserEnv is the whole environment of a runner. A root LaunchDaemon starts
// with launchd's minimal one, so everything the runner needs is written here and
// nothing is inherited: a job must not read what the agent was started with.
// There is no RUNNER_ALLOW_RUNASROOT, because the runner is never root. The
// pool's own settings come last and win. cacheDir is the slot's persistent cache
// folder, which is empty, and is then not mentioned, when the pool keeps no cache.
func jobUserEnv(s *jobUserSlot, home, tmpDir, cacheDir string, spec Spec) []string {
	env := []string{
		"HOME=" + home,
		"USER=" + s.name,
		"LOGNAME=" + s.name,
		"SHELL=" + jobUserShell,
		"PATH=" + jobUserPath,
		"LANG=" + jobUserLocale,
		"LC_ALL=" + jobUserLocale,
		EnvRunnerName + "=" + spec.Name,
		EnvEphemeral + "=" + boolString(spec.Ephemeral),
		EnvUpstreamJITConfig + "=" + spec.Credentials.JITConfig,
	}
	if tmpDir != "" {
		env = append(env, "TMPDIR="+tmpDir)
	}
	if cacheDir != "" {
		env = append(env, EnvCacheDir+"="+cacheDir)
	}
	keys := make([]string, 0, len(spec.Env))
	for k := range spec.Env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		env = append(env, k+"="+spec.Env[k])
	}
	return env
}
