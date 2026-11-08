#!/usr/bin/env bash
# One command to bring up, check and tear down the LOCAL buyer-path stack on loopback.
# Nothing here is hosted, nothing is a real credential, no Stripe/Fly/GHCR is contacted.
#
#   scripts/local-stack.sh verify    up, run scripts/verify-buyer-path.sh against it, ALWAYS down
#   scripts/local-stack.sh up        start the stack and leave it running (prints the verify command)
#   scripts/local-stack.sh down      stop it, drop ITS database, delete ITS data directory
#   scripts/local-stack.sh status    what is recorded as running
#
# What `up` starts (all on 127.0.0.1):
#   - a NEW throwaway PostgreSQL database  nb_local_<random>  (seeded from deploy/ai/seed.sql) on the
#     server named by NEURALBRIDGE_AI_PG_{HOST,PORT,USER,PASSWORD} (default: the documented local dev
#     role in docs/ai-local-setup.md: neuralbridge / neuralbridge_dev @ 127.0.0.1:5432). That role must
#     be allowed to create databases. It never touches a database it did not create, and `down` drops
#     only the name recorded in its own state file.
#   - the Assurance API (assurance.api.service:app)  on API_PORT (8001)
#   - the NeuralBridge platform API incl. /ai (neuralbridge.main:app) on PLATFORM_PORT (8000), with the
#     LOCAL-ONLY switch NEURALBRIDGE_AI_DEMO_WRITABLE_BY_PAID=1 so a paid account may write the shared
#     seeded demo connection (never set this in production)
#   both sharing ONE ASSURANCE_ACCOUNTS path, which is what makes one key work on both surfaces.
#   An operator key (>= 32 characters) is generated per run into a 0600 file in the data directory.
#   It is never printed.
#
# Env (all optional): PYTHON (default python; needs the repo's deps, `pip install -e '.[dev]'`),
#   LOCAL_STACK_DIR (default /tmp/nb-demo), API_PORT, PLATFORM_PORT, NEURALBRIDGE_AI_PG_*.
# Exit: `verify` returns verify-buyer-path.sh's status | 2 could not start (port busy, no Postgres,
#   server did not come up, stack already up).
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
ROOT="$PWD"
PYTHON="${PYTHON:-python}"
DIR="${LOCAL_STACK_DIR:-/tmp/nb-demo}"
API_PORT="${API_PORT:-8001}"
PLATFORM_PORT="${PLATFORM_PORT:-8000}"
STATE="$DIR/state.env"
MARKER="$DIR/.nb-local-stack"   # written by `up`; `down` removes only a directory that carries it

export NEURALBRIDGE_AI_PG_HOST="${NEURALBRIDGE_AI_PG_HOST:-127.0.0.1}"
export NEURALBRIDGE_AI_PG_PORT="${NEURALBRIDGE_AI_PG_PORT:-5432}"
export NEURALBRIDGE_AI_PG_USER="${NEURALBRIDGE_AI_PG_USER:-neuralbridge}"
export NEURALBRIDGE_AI_PG_PASSWORD="${NEURALBRIDGE_AI_PG_PASSWORD:-neuralbridge_dev}"

# A scrubbed environment: no Stripe or deployment setting of the caller can reach the children. Only the
# PostgreSQL connection settings read above are kept (everything else is set explicitly below).
for v in $(compgen -e); do
  case "$v" in
    STRIPE_*|ASSURANCE_*) unset "$v" ;;
    NEURALBRIDGE_AI_PG_HOST|NEURALBRIDGE_AI_PG_PORT|NEURALBRIDGE_AI_PG_USER|NEURALBRIDGE_AI_PG_PASSWORD) ;;
    NEURALBRIDGE_*) unset "$v" ;;
  esac
done

die() { echo "local-stack: $*" >&2; exit 2; }

busy() { curl -s -o /dev/null --max-time 2 "http://127.0.0.1:$1/"; }

# Stop one recorded process group, but only if the pid still belongs to a uvicorn we started.
stop_pid() {
  local pid="$1"
  [ -n "$pid" ] || return 0
  if [ -r "/proc/$pid/cmdline" ] && tr '\0' ' ' <"/proc/$pid/cmdline" | grep -q uvicorn; then
    kill -- "-$pid" 2>/dev/null || kill "$pid" 2>/dev/null
    for _ in 1 2 3 4 5 6 7 8 9 10; do kill -0 "$pid" 2>/dev/null || break; sleep 0.5; done
    kill -9 -- "-$pid" 2>/dev/null || true
  fi
}

# The directory must be a real directory (not a symlink), ours, and not writable by group or others:
# a predictable path in /tmp may have been planted by someone else.
dir_is_safe() {
  [ -n "$DIR" ] && [ "$DIR" != "/" ] && [ -d "$DIR" ] && [ ! -L "$DIR" ] || return 1
  local owner mode
  owner="$(stat -c %u -- "$DIR" 2>/dev/null)" || return 1
  mode="$(stat -c %a -- "$DIR" 2>/dev/null)" || return 1
  [ "$owner" = "$(id -u)" ] || return 1
  [ $(( 8#$mode & 8#022 )) -eq 0 ]
}

# Read the state file as DATA. It is never sourced or evaluated: only these keys, only these value
# shapes. Anything else (an unknown key, a bad value, a line that is not KEY=VALUE) refuses the file.
S_API_PID="" S_PLATFORM_PID="" S_DB_NAME=""
read_state() {
  S_API_PID="" S_PLATFORM_PID="" S_DB_NAME=""
  [ -f "$STATE" ] && [ ! -L "$STATE" ] || { echo "local-stack: $STATE is not a regular file" >&2; return 1; }
  local line key val
  while IFS= read -r line || [ -n "$line" ]; do
    [ -n "$line" ] || continue
    case "$line" in
      *=*) key="${line%%=*}"; val="${line#*=}" ;;
      *) echo "local-stack: refusing $STATE: a line that is not KEY=VALUE" >&2; return 1 ;;
    esac
    case "$key" in
      API_PID|PLATFORM_PID)
        [[ "$val" =~ ^[0-9]{1,10}$ ]] || { echo "local-stack: refusing $STATE: $key is not a pid" >&2; return 1; }
        if [ "$key" = API_PID ]; then S_API_PID="$val"; else S_PLATFORM_PID="$val"; fi ;;
      DB_NAME)
        [[ "$val" =~ ^nb_local_[a-z0-9]+$ ]] || { echo "local-stack: refusing $STATE: DB_NAME is not a nb_local_ name" >&2; return 1; }
        S_DB_NAME="$val" ;;
      API_PORT|PLATFORM_PORT)
        [[ "$val" =~ ^[0-9]{1,5}$ ]] || { echo "local-stack: refusing $STATE: $key is not a port" >&2; return 1; } ;;
      *) echo "local-stack: refusing $STATE: unexpected key" >&2; return 1 ;;
    esac
  done <"$STATE"
}

do_down() {
  if [ ! -f "$STATE" ]; then
    echo "local-stack: nothing recorded in $STATE (already down)" >&2
    return 0
  fi
  if ! dir_is_safe || [ ! -f "$MARKER" ] || [ -L "$MARKER" ]; then
    echo "local-stack: refusing to act on $DIR: not a directory this script created (missing marker), not owned by you, or group/world-writable. Nothing was run or removed." >&2
    return 2
  fi
  read_state || return 2
  local API_PID="$S_API_PID" PLATFORM_PID="$S_PLATFORM_PID" DB_NAME="$S_DB_NAME"
  stop_pid "${API_PID:-}"
  stop_pid "${PLATFORM_PID:-}"
  local rc=0
  if [ -n "${DB_NAME:-}" ]; then
    "$PYTHON" scripts/local_stack_db.py drop "$DB_NAME" || rc=1
  fi
  if [ "$rc" = 0 ]; then
    rm -rf "$DIR" "$DIR.custody"
    echo "local-stack: down; database ${DB_NAME:-?} dropped, $DIR removed" >&2
  else
    echo "local-stack: processes stopped but the database drop failed; $DIR kept so \`down\` can be retried" >&2
  fi
  return "$rc"
}

wait_for() {  # $1 url $2 label $3 log
  for _ in $(seq 1 60); do
    curl -fs --max-time 2 "$1" >/dev/null 2>&1 && return 0
    sleep 1
  done
  echo "local-stack: $2 did not come up; last lines of $3:" >&2
  tail -15 "$3" >&2
  return 1
}

do_up() {
  [ ! -e "$STATE" ] || die "a stack is already recorded in $STATE; run: scripts/local-stack.sh down"
  if [ -e "$DIR" ] || [ -L "$DIR" ]; then
    dir_is_safe || die "$DIR already exists and is not a private directory owned by you (planted?); set LOCAL_STACK_DIR or remove it"
  fi
  [ ! -e "$DIR" ] || [ -z "$(ls -A "$DIR" 2>/dev/null)" ] || die "$DIR exists and is not empty (not ours?); set LOCAL_STACK_DIR or remove it"
  for p in "$API_PORT" "$PLATFORM_PORT"; do
    busy "$p" && die "port $p is already serving something; refusing to start beside an unknown server (set API_PORT / PLATFORM_PORT)"
  done
  "$PYTHON" -c 'import uvicorn, fastapi, asyncpg, assurance, neuralbridge' 2>/dev/null \
    || die "$PYTHON cannot import uvicorn/fastapi/asyncpg/assurance/neuralbridge; pip install -e '.[dev]' (or set PYTHON)"

  # Create the directory ourselves, mode 0700, or accept an EMPTY one that is already ours and private.
  if [ -e "$DIR" ] || [ -L "$DIR" ]; then
    dir_is_safe || die "$DIR already exists and is not a private directory owned by you (planted?); set LOCAL_STACK_DIR or remove it"
  else
    ( umask 077; mkdir -- "$DIR" ) || die "cannot create $DIR"
  fi
  chmod 700 "$DIR" || die "cannot restrict $DIR"
  dir_is_safe || die "$DIR is not safe to use"
  [ ! -e "$DIR.custody" ] && [ ! -L "$DIR.custody" ] || die "$DIR.custody already exists; remove it or set LOCAL_STACK_DIR"
  ( umask 077; : >"$MARKER" ) || die "cannot write $MARKER"
  local suffix db
  suffix="$("$PYTHON" -c 'import secrets; print(secrets.token_hex(4))')"
  db="nb_local_${suffix}"
  # Record before creating anything, so `down` can always find what to remove.
  { echo "DB_NAME=$db"; echo "API_PORT=$API_PORT"; echo "PLATFORM_PORT=$PLATFORM_PORT"; } >"$STATE"

  "$PYTHON" scripts/local_stack_db.py create "$db" --seed deploy/ai/seed.sql >&2 \
    || { do_down; die "could not create the throwaway database (is PostgreSQL up at $NEURALBRIDGE_AI_PG_HOST:$NEURALBRIDGE_AI_PG_PORT, and may the role create databases?)"; }

  # Operator key: generated here, written 0600, never printed. >= 32 characters (MIN_OPERATOR_KEY_LENGTH).
  ( umask 077; "$PYTHON" -c 'import secrets; print(secrets.token_urlsafe(32))' >"$DIR/operator.key" )

  export PYTHONPATH="$ROOT/src" PYTHONDONTWRITEBYTECODE=1 ASSURANCE_ACCOUNTS="$DIR/accounts.db" ASSURANCE_HOST=127.0.0.1
  # The key goes in through the child's environment (a subshell export), not its command line, so
  # `ps` never shows it.
  (
    ASSURANCE_API_KEYS="$(cat "$DIR/operator.key")"; export ASSURANCE_API_KEYS
    export ASSURANCE_LEDGER="$DIR/art14.db"
    setsid "$PYTHON" -m uvicorn assurance.api.service:app --host 127.0.0.1 --port "$API_PORT" >"$DIR/assurance.log" 2>&1 &
    echo "API_PID=$!" >>"$STATE"
  )
  (
    export NEURALBRIDGE_AI_PG_DATABASE="$db" NEURALBRIDGE_AI_STORE="$DIR/ai-store.db"
    export NEURALBRIDGE_AI_DEMO_WRITABLE_BY_PAID=1   # LOCAL ONLY: the demo connection is writable by a paid account
    # Credential custody fails closed without a key and a journal kept OUTSIDE the store's directory.
    # A random per-run key, in this subshell's environment only (never printed, never in argv).
    ( umask 077; mkdir -- "$DIR.custody" ) && chmod 700 "$DIR.custody"
    NEURALBRIDGE_CREDENTIAL_KEYS="local:$("$PYTHON" -c 'import base64,os;print(base64.b64encode(os.urandom(32)).decode())')"
    export NEURALBRIDGE_CREDENTIAL_KEYS NEURALBRIDGE_CREDENTIAL_JOURNAL="$DIR.custody/journal"
    setsid "$PYTHON" -m uvicorn neuralbridge.main:app --host 127.0.0.1 --port "$PLATFORM_PORT" >"$DIR/platform.log" 2>&1 &
    echo "PLATFORM_PID=$!" >>"$STATE"
  )

  if ! wait_for "http://127.0.0.1:$API_PORT/v1/plans" "the Assurance API" "$DIR/assurance.log" \
     || ! wait_for "http://127.0.0.1:$PLATFORM_PORT/api/v1/ai/connections" "the platform API" "$DIR/platform.log"; then
    do_down
    exit 2
  fi
  cat >&2 <<EOF
local-stack: up. Assurance API :$API_PORT, platform API :$PLATFORM_PORT, database $db, data $DIR
  ASSURANCE_API_URL=http://127.0.0.1:$API_PORT NEURALBRIDGE_API_URL=http://127.0.0.1:$PLATFORM_PORT/api/v1 \\
  ASSURANCE_ACCOUNTS=$DIR/accounts.db scripts/verify-buyer-path.sh
  tear down with: scripts/local-stack.sh down
EOF
}

do_verify() {
  do_up || exit $?
  trap 'do_down' EXIT
  local rc=0
  ASSURANCE_API_URL="http://127.0.0.1:$API_PORT" \
  NEURALBRIDGE_API_URL="http://127.0.0.1:$PLATFORM_PORT/api/v1" \
  ASSURANCE_ACCOUNTS="$DIR/accounts.db" PYTHON="$PYTHON" PYTHONPATH="$ROOT/src" \
    scripts/verify-buyer-path.sh || rc=$?
  echo "local-stack: verify-buyer-path.sh exit status $rc" >&2
  exit "$rc"
}

case "${1:-}" in
  verify) do_verify ;;
  up)     do_up ;;
  down)   do_down ;;
  status)
    if [ -f "$STATE" ]; then echo "recorded in $STATE:"; cat "$STATE"; else echo "no stack recorded"; fi ;;
  *) sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2 ;;
esac
