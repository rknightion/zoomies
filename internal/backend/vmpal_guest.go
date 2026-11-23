package backend

import (
	_ "embed"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// vmpalHelperScript is what the agent installs in every clone. It is embedded
// rather than kept in the template so that a template cannot hold an older
// helper than the parsers below expect.
//
//go:embed vmpal_guest.sh
var vmpalHelperScript string

const (
	// vmpalHelperPath is relative because exec starts in the account's home and
	// has no shell to expand a variable.
	vmpalHelperPath = ".zoomies/helper.sh"
	// vmpalHelperVar and vmpalEnvVar are passed with --env NAME, so neither
	// value is ever an argument on the Mac.
	vmpalHelperVar = "ZOOMIES_HELPER_B64"
	vmpalEnvVar    = "ZOOMIES_ENV_B64"
	// vmpalLogChunk is the most one log read asks for or the host accepts.
	vmpalLogChunk = 256 << 10
)

const vmpalInstallScript = `umask 077 && mkdir -p "$HOME/.zoomies" && printf %s "$ZOOMIES_HELPER_B64" | /usr/bin/base64 -D > "$HOME/.zoomies/helper.sh" && chmod 700 "$HOME/.zoomies/helper.sh"`

func vmpalInstallArgv() []string { return []string{"/bin/sh", "-c", vmpalInstallScript} }

func vmpalHelperArgv(sub string, args ...string) []string {
	return append([]string{"/bin/sh", vmpalHelperPath, sub}, args...)
}

// The grammars of the helper's answers. They are anchored and exact because
// from the moment a job has run, the guest writes them: anything that is not
// precisely this is a failed step, and is never read for what it nearly says.
var (
	vmpalSessionLine = regexp.MustCompile(`^zoomies-session v1 uid=([0-9]{1,10}) gui=1$`)
	vmpalArmLine     = regexp.MustCompile(`^zoomies-arm v1 ok source=(cache|download)$`)
	vmpalExitLine    = regexp.MustCompile(`^zoomies-exit v1 code=(0|[1-9][0-9]{0,2}) job=([01])$`)
	vmpalLogLine     = regexp.MustCompile(`^zoomies-log v1 next=([0-9]{1,18}) size=([0-9]{1,18})$`)
)

const (
	vmpalExitRunning = "zoomies-exit v1 running"
	vmpalDeliverOK   = "zoomies-deliver v1 ok"
	vmpalStartOK     = "zoomies-start v1 ok"
	vmpalStopOK      = "zoomies-stop v1 ok"
)

var errVMPalGuestAnswer = errors.New("the guest's helper gave an answer this version of Zoomies cannot read")

// vmpalAnswer is the one line a subcommand printed. A second line is not
// tolerated, because it is the difference between a record and a record
// someone appended to.
func vmpalAnswer(stdout string) string { return strings.TrimSuffix(stdout, "\n") }

func parseVMPalSession(stdout string) error {
	if !vmpalSessionLine.MatchString(vmpalAnswer(stdout)) {
		return errVMPalGuestAnswer
	}
	return nil
}

func parseVMPalArm(stdout string) (source string, err error) {
	m := vmpalArmLine.FindStringSubmatch(vmpalAnswer(stdout))
	if m == nil {
		return "", errVMPalGuestAnswer
	}
	return m[1], nil
}

func checkVMPalLine(stdout, want string) error {
	if vmpalAnswer(stdout) != want {
		return errVMPalGuestAnswer
	}
	return nil
}

// vmpalGuestExit is the guest's exit record.
type vmpalGuestExit struct {
	Code    int
	TookJob bool
}

// parseVMPalExit reads the exit subcommand's answer. running is true while the
// runner has not finished; an error means the record cannot be believed.
func parseVMPalExit(stdout string) (exit vmpalGuestExit, running bool, err error) {
	line := vmpalAnswer(stdout)
	if line == vmpalExitRunning {
		return exit, true, nil
	}
	m := vmpalExitLine.FindStringSubmatch(line)
	if m == nil {
		return exit, false, errVMPalGuestAnswer
	}
	code, err := strconv.Atoi(m[1])
	if err != nil || code > 255 {
		return exit, false, errVMPalGuestAnswer
	}
	return vmpalGuestExit{Code: code, TookJob: m[2] == "1"}, false, nil
}

// parseVMPalLog reads one log response: its header line, then that many bytes
// in base64. A header and body that disagree are refused rather than trimmed,
// since either may be what the job chose to print.
func parseVMPalLog(stdout string, limit int64) (data []byte, next int64, err error) {
	header, body, _ := strings.Cut(stdout, "\n")
	m := vmpalLogLine.FindStringSubmatch(header)
	if m == nil {
		return nil, 0, errVMPalGuestAnswer
	}
	next, err = strconv.ParseInt(m[1], 10, 64)
	if err != nil {
		return nil, 0, errVMPalGuestAnswer
	}
	size, err := strconv.ParseInt(m[2], 10, 64)
	if err != nil || size > limit || size > next {
		return nil, 0, errVMPalGuestAnswer
	}
	data, err = base64.StdEncoding.DecodeString(strings.Join(strings.Fields(body), ""))
	if err != nil || int64(len(data)) != size {
		return nil, 0, errVMPalGuestAnswer
	}
	return data, next, nil
}

var vmpalEnvName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// vmpalEnvPayload is the runner's environment as one base64 value of NAME=value
// lines. It travels as one value so that nothing a pool sets can become a
// variable of the vmpal process on the Mac. A value with a line break would be
// read in the guest as a second variable, so it is refused rather than escaped.
func vmpalEnvPayload(spec Spec) (string, error) {
	lines := []string{EnvRunnerName + "=" + spec.Name, EnvEphemeral + "=true"}
	names := make([]string, 0, len(spec.Env))
	for name := range spec.Env {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		value := spec.Env[name]
		switch {
		case !vmpalEnvName.MatchString(name):
			return "", fmt.Errorf("%w: pool %q sets an environment variable named %q, which is not a valid name; rename it", ErrBackendConfig, spec.PoolName, name)
		case name == EnvUpstreamJITConfig || name == EnvJITConfig:
			return "", fmt.Errorf("%w: pool %q sets %s, which Zoomies keeps for the runner's registration; remove it from the pool", ErrBackendConfig, spec.PoolName, name)
		case strings.ContainsAny(value, "\r\n\x00"):
			return "", fmt.Errorf("%w: pool %q sets %s to a value with a line break, which a macOS VM runner cannot carry; put it on one line", ErrBackendConfig, spec.PoolName, name)
		}
		lines = append(lines, name+"="+value)
	}
	return base64.StdEncoding.EncodeToString([]byte(strings.Join(lines, "\n") + "\n")), nil
}
