#!/usr/bin/env bash
#
# Runs testhub <n> as a standalone hub (Yivi login, no PubHubs Central or global client):
# the hub server and hub client, side by side in a tmux session.

set -e

n="$1"
SESSION="pubhubs-standalone-$n"

# Otherwise both panes fail on the taken container name and ports, and only say so inside tmux
if docker ps --format '{{.Names}}' | grep -qx "pubhubs-testhub$n"; then
	echo "testhub$n is already running (e.g. from 'mask run all'); stop it, or pick another n" >&2
	exit 1
fi
if tmux has-session -t "$SESSION" 2>/dev/null; then
	echo "tmux session $SESSION already exists; attach with 'tmux attach -t $SESSION'" >&2
	exit 1
fi

python3 scripts/enable-standalone-hub.py "$n"

# See run-all.sh
hold='echo "=== command finished; press Ctrl+C to close this pane ==="; sleep 3600'

hub_server_flags=()
[[ "$PH_NO_POSTGRES" == "true" ]] && hub_server_flags=(--no-postgres)

tmux new-session -d -s "$SESSION" -n hub "mask run hub server $n ${hub_server_flags[*]}; $hold"

# Like run-all-cleanup.sh: Ctrl+C until the session is gone, so the hub container can exit cleanly
function cleanup() {
	while tmux send-keys -t "$SESSION" C-c 2>/dev/null; do
		sleep 0.1
	done
}

trap 'cleanup' SIGINT EXIT

sleep 0.2

tmux split-window -h -t "$SESSION:0" "echo 'Open http://localhost:$((8001 + n)) to log in with Yivi'; mask run hub client $n; $hold"
tmux select-layout -t "$SESSION:0" even-horizontal

tmux attach -t "$SESSION"
