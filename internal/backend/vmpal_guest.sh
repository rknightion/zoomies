#!/bin/sh
# The agent's half of a macOS guest. The agent installs this file in every clone
# and calls one subcommand at a time through vmpal exec, because exec has no
# shell of its own and each step needs one. It holds no secret.
#
# Output is a contract: the host parses each answer strictly and treats anything
# else as a failure of that step. Once a job has run, the guest belongs to the
# job, so nothing here is trusted by the host either.
#
# PATH is fixed for the helper's own commands. The runner gets the one it was
# started with, which under launchd is only the system folders, so the usual
# tool folders are added after them.

set -u
umask 077
RUNNER_PATH=${PATH:-/usr/bin:/bin:/usr/sbin:/sbin}
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH

LAUNCHCTL=/bin/launchctl
BASE64=/usr/bin/base64
SHASUM=/usr/bin/shasum
CURL=/usr/bin/curl
TAR=/usr/bin/tar
PERL=/usr/bin/perl

ZDIR="$HOME/.zoomies"
RUNNER_DIR="$ZDIR/runner"
LOG_FILE="$ZDIR/runner.log"
EXIT_FILE="$ZDIR/exit"
JIT_FILE="$ZDIR/jit"
ENV_FILE="$ZDIR/env"
LABEL=dev.zoomies.runner
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
CACHE_DIR=/Library/Caches/zoomies

die() {
	printf 'zoomies-helper: %s\n' "$1" >&2
	exit 1
}

is_number() {
	case "$1" in
	'' | *[!0-9]*) return 1 ;;
	esac
	[ "${#1}" -le 18 ]
}

guest_uid() {
	uid=$(/usr/bin/id -u) || die "could not read this account's user ID"
	is_number "$uid" || die "this account's user ID is not a number"
}

# The runner has to start in the logged-in session, because keychain work in a
# job needs one. A domain that answers is one launchctl bootstrap can use.
cmd_session() {
	guest_uid
	"$LAUNCHCTL" print "gui/$uid" >/dev/null 2>&1 ||
		die "no user is signed in to this VM; set the template up so VMPal can sign its account in"
	printf 'zoomies-session v1 uid=%s gui=1\n' "$uid"
}

# Every target is tried, because a must-block target that answers is the one
# result that matters most. Perl is used for the time-limited connect that sh
# cannot do. $! is cleared first so a stale error can never read as a timeout,
# which is the one answer that passes a must-block target.
cmd_egress() {
	[ -n "${ZOOMIES_EGRESS_TARGETS:-}" ] || die "no egress targets were given"
	# shellcheck disable=SC2016 # the program is Perl, and its variables are Perl's
	"$PERL" -e '
use strict; use warnings;
use IO::Socket::IP; use Socket qw(SOCK_STREAM);
use Errno qw(ECONNREFUSED ETIMEDOUT ENETUNREACH EHOSTUNREACH);
sub word { my $e = shift;
  return "refused" if $e == ECONNREFUSED;
  return "timeout" if $e == ETIMEDOUT;
  return "unreachable" if $e == ENETUNREACH || $e == EHOSTUNREACH;
  return "error"; }
sub try { my ($target) = @_;
  my ($host, $port) = $target =~ /^\[?([^\[\]\s]+?)\]?:([0-9]{1,5})$/ or return "error";
  $! = 0;
  my $s = IO::Socket::IP->new(PeerHost => $host, PeerPort => $port, Type => SOCK_STREAM, Timeout => 5);
  return "connected" if $s;
  return word($! + 0); }
$| = 1; my $i = 0;
for my $t (split " ", $ENV{ZOOMIES_EGRESS_TARGETS}) {
  print "zoomies-egress v1 target $i ", try($t), "\n"; $i++; }
print "zoomies-egress v1 end $i\n";
' || die "the egress check could not run"
}

digest_of() {
	"$SHASUM" -a 256 "$1" | { read -r sum _ && printf '%s' "$sum"; }
}

# A cached archive is only a shortcut: it is held to the same digest as a
# download, and one that fails is ignored in favour of fetching the real thing.
cmd_arm() {
	[ $# -eq 3 ] || die "arm needs a version, a digest and a URL"
	version=$1 want=$2 url=$3
	case "$version" in
	'' | *[!0-9.]*) die "that is not a runner version" ;;
	esac
	case "$want" in
	*[!0-9a-f]*) die "that is not a SHA-256" ;;
	esac
	[ "${#want}" -eq 64 ] || die "that is not a SHA-256"

	cache="$CACHE_DIR/actions-runner-osx-arm64-$version.tar.gz"
	if [ -f "$cache" ] && [ "$(digest_of "$cache")" = "$want" ]; then
		archive=$cache source=cache
	else
		archive="$ZDIR/runner.tar.gz" source=download
		rm -f "$archive"
		"$CURL" -fsSL --max-time 150 -o "$archive" "$url" ||
			die "could not download the runner; check that this VM can reach the release"
		if [ "$(digest_of "$archive")" != "$want" ]; then
			rm -f "$archive"
			die "the runner download does not match its expected SHA-256"
		fi
	fi

	rm -rf "$RUNNER_DIR"
	mkdir -p "$RUNNER_DIR" || die "could not create the runner folder"
	"$TAR" -xzf "$archive" -C "$RUNNER_DIR" || die "could not unpack the runner"
	[ "$source" = cache ] || rm -f "$archive"
	[ -x "$RUNNER_DIR/run.sh" ] || die "the runner archive has no run.sh"
	printf 'zoomies-arm v1 ok source=%s\n' "$source"
}

# The credential arrives in this process's environment, which is the only place
# it has been on its way here, and leaves it for a file only this account can
# read. The wrapper below deletes that file as it reads it.
cmd_deliver() {
	[ -n "${ACTIONS_RUNNER_INPUT_JITCONFIG:-}" ] || die "no runner registration was delivered"
	printf '%s' "$ACTIONS_RUNNER_INPUT_JITCONFIG" >"$JIT_FILE.tmp" ||
		die "could not store the runner registration"
	mv -f "$JIT_FILE.tmp" "$JIT_FILE" || die "could not store the runner registration"
	if [ -n "${ZOOMIES_ENV_B64:-}" ]; then
		printf '%s' "$ZOOMIES_ENV_B64" | "$BASE64" -D >"$ENV_FILE.tmp" ||
			die "could not decode the runner environment"
	else
		: >"$ENV_FILE.tmp"
	fi
	mv -f "$ENV_FILE.tmp" "$ENV_FILE" || die "could not store the runner environment"
	printf 'zoomies-deliver v1 ok\n'
}

xml_escape() {
	printf '%s' "$1" | /usr/bin/sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'
}

# A LaunchAgent and not a child of exec: the runner has to outlive the exec that
# started it, and it has to be in the logged-in session.
cmd_start() {
	[ -s "$JIT_FILE" ] || die "there is no runner registration to start with"
	[ -x "$RUNNER_DIR/run.sh" ] || die "the runner has not been unpacked"
	guest_uid
	mkdir -p "$HOME/Library/LaunchAgents" || die "could not create the LaunchAgents folder"
	helper=$(xml_escape "$ZDIR/helper.sh")
	log=$(xml_escape "$LOG_FILE")
	dir=$(xml_escape "$RUNNER_DIR")
	cat >"$PLIST" <<EOF || die "could not write the runner's LaunchAgent"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>$LABEL</string>
<key>ProgramArguments</key><array><string>/bin/sh</string><string>$helper</string><string>run</string></array>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><false/>
<key>ProcessType</key><string>Interactive</string>
<key>WorkingDirectory</key><string>$dir</string>
<key>StandardOutPath</key><string>$log</string>
<key>StandardErrorPath</key><string>$log</string>
</dict></plist>
EOF
	"$LAUNCHCTL" bootstrap "gui/$uid" "$PLIST" || die "launchctl would not start the runner"
	printf 'zoomies-start v1 ok\n'
}

# Written by rename, so the host never reads half a record.
write_exit() {
	printf 'zoomies-exit v1 code=%s job=%s\n' "$1" "$2" >"$EXIT_FILE.tmp" &&
		mv -f "$EXIT_FILE.tmp" "$EXIT_FILE"
}

# What launchd runs. The registration is read and deleted before the listener
# exists, so nothing the job does can find it on disk.
cmd_run() {
	jit=
	[ -f "$JIT_FILE" ] && jit=$(cat "$JIT_FILE")
	rm -f "$JIT_FILE"
	if [ -z "$jit" ]; then
		write_exit 1 0
		die "there was no runner registration to read"
	fi
	# Homebrew goes last so nothing in it can shadow the Xcode toolchain. A pool's
	# own settings are read after these defaults and win.
	PATH=$RUNNER_PATH
	for dir in /usr/local/bin /opt/homebrew/bin /opt/homebrew/sbin; do
		case ":$PATH:" in
		*":$dir:"*) ;;
		*) PATH=$PATH:$dir ;;
		esac
	done
	export PATH
	export LANG="${LANG:-en_US.UTF-8}" LC_ALL="${LC_ALL:-en_US.UTF-8}"
	if [ -f "$ENV_FILE" ]; then
		while IFS= read -r line || [ -n "$line" ]; do
			name=${line%%=*}
			case "$name" in
			'' | [!A-Za-z_]* | *[!A-Za-z0-9_]*) continue ;;
			esac
			# shellcheck disable=SC2163 # the line is NAME=value, exported whole
			export "$line"
		done <"$ENV_FILE"
		rm -f "$ENV_FILE"
	fi
	if ! cd "$RUNNER_DIR"; then
		write_exit 1 0
		die "the runner folder is missing"
	fi

	# A background job of a shell without job control starts with SIGINT ignored,
	# and a script cannot trap what was ignored when it started, so the stop below
	# would never reach the runner. Perl puts the default back and becomes run.sh.
	# The helper's umask is for its own files: under it, a checkout writes a
	# tracked 0755 script as 0700. The subshell execs, so $! is still the runner.
	# shellcheck disable=SC2016 # the program is Perl, and its variables are Perl's
	(umask 022 && ACTIONS_RUNNER_INPUT_JITCONFIG=$jit exec "$PERL" -e '$SIG{INT} = $SIG{QUIT} = "DEFAULT"; exec { $ARGV[0] } @ARGV or exit 127' ./run.sh) &
	child=$!
	unset jit
	trap 'kill -INT "$child" 2>/dev/null' INT
	trap 'kill -TERM "$child" 2>/dev/null' TERM

	# A signal ends wait early with the child still alive, so wait again until
	# it really has gone. The last wait is what holds its exit status.
	code=0
	while :; do
		wait "$child"
		code=$?
		kill -0 "$child" 2>/dev/null || break
	done
	wait "$child" 2>/dev/null
	last=$?
	[ "$last" -eq 127 ] || code=$last

	# A runner that took a job has left a worker log. It is the only evidence
	# of that which survives the runner, and the breaker counts on it.
	job=0
	for f in "$RUNNER_DIR"/_diag/Worker_*; do
		[ -e "$f" ] && job=1
		break
	done
	write_exit "$code" "$job"
	exit "$code"
}

cmd_exit() {
	if [ -f "$EXIT_FILE" ]; then
		head -c 128 "$EXIT_FILE"
	else
		printf 'zoomies-exit v1 running\n'
	fi
}

# Base64, because vmpal reads what a command prints as UTF-8 and would rewrite
# whatever a build logged that is not.
cmd_log() {
	[ $# -eq 2 ] || die "log needs an offset and a size"
	is_number "$1" || die "log's offset must be a number"
	is_number "$2" || die "log's size must be a number"
	offset=$1 max=$2 total=0
	[ -f "$LOG_FILE" ] && total=$(wc -c <"$LOG_FILE" | tr -d ' ')
	[ "$offset" -le "$total" ] || offset=$total
	size=$((total - offset))
	[ "$size" -le "$max" ] || size=$max
	printf 'zoomies-log v1 next=%s size=%s\n' "$((offset + size))" "$size"
	[ "$size" -eq 0 ] || tail -c +"$((offset + 1))" "$LOG_FILE" | head -c "$size" | "$BASE64"
}

cmd_stop() {
	if [ ! -f "$EXIT_FILE" ]; then
		guest_uid
		"$LAUNCHCTL" kill SIGINT "gui/$uid/$LABEL" || die "could not signal the runner"
	fi
	printf 'zoomies-stop v1 ok\n'
}

[ $# -gt 0 ] || die "a subcommand is required"
command=$1
shift
case "$command" in
session) cmd_session ;;
egress) cmd_egress ;;
arm) cmd_arm "$@" ;;
deliver) cmd_deliver ;;
start) cmd_start ;;
run) cmd_run ;;
exit) cmd_exit ;;
log) cmd_log "$@" ;;
stop) cmd_stop ;;
*) die "unknown subcommand" ;;
esac
