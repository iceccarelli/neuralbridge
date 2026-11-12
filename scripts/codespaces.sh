#!/usr/bin/env bash
# One entry point for working on NeuralBridge from a terminal (Codespaces or any Debian/Ubuntu box).
#
#   bash scripts/codespaces.sh status    read-only: git, GitHub auth, open PRs, CI on main, the nightly
#                                        stress run, toolchain, Postgres. Changes nothing.
#   bash scripts/codespaces.sh setup     installs what the test gate needs: Python deps (hash-checked
#                                        lock), Node deps, a local throwaway PostgreSQL 16 with the
#                                        repository's published dev credentials. Idempotent.
#   bash scripts/codespaces.sh verify    the definition of done from CLAUDE.md: ruff, capabilities
#                                        check, the full pytest suite with Postgres and Node REQUIRED
#                                        (a skip is a gate that did not run), tsc and the site build.
#   bash scripts/codespaces.sh e2e       the browser suite (real API + Postgres + Next + Chromium).
#   bash scripts/codespaces.sh stress    the independent stress-test authority against this checkout.
#   bash scripts/codespaces.sh ci [N]    the latest CI runs on main (or watch pull request N).
#   bash scripts/codespaces.sh all       status, setup, verify, e2e, stress, in that order.
#
# Never deploys, never touches Stripe, DNS or any secret, never merges, never pushes. The only
# credentials it uses are the throwaway ones already published in .github/workflows/ci.yml for the
# CI service container (a database that only exists on this machine).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PG_HOST=127.0.0.1
PG_PORT=5432
PG_USER=neuralbridge
PG_PASS=neuralbridge_dev          # the CI service container's published dev password; not a secret
PG_DB_TEST=neuralbridge_ai_test
PG_DB_E2E=neuralbridge_ai_e2e
PG_DIR="${NB_PG_DIR:-$HOME/.local/share/nb-pg}"
REPO_SLUG="${NB_REPO:-iceccarelli/neuralbridge}"
STRESS_SLUG="iceccarelli/neuralbridge-stress-test"
STRESS_DIR="${NB_STRESS_DIR:-$ROOT/../neuralbridge-stress-test}"

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
ok()   { printf '  \033[32mok\033[0m   %s\n' "$*"; }
warn() { printf '  \033[33mwarn\033[0m %s\n' "$*"; }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$*"; FAILED=1; }
have() { command -v "$1" >/dev/null 2>&1; }
FAILED=0

pg_env() {
  export NEURALBRIDGE_AI_PG_HOST=$PG_HOST NEURALBRIDGE_AI_PG_PORT=$PG_PORT \
         NEURALBRIDGE_AI_PG_USER=$PG_USER NEURALBRIDGE_AI_PG_PASSWORD=$PG_PASS \
         NEURALBRIDGE_AI_PG_TEST_DATABASE="${1:-$PG_DB_TEST}" \
         NEURALBRIDGE_REQUIRE_POSTGRES=1 NEURALBRIDGE_REQUIRE_NODE=1
}

pg_up() { have pg_isready && pg_isready -q -h "$PG_HOST" -p "$PG_PORT"; }

cmd_status() {
  say "git"
  git fetch -q origin 2>/dev/null || warn "could not fetch origin"
  printf '  branch: %s\n' "$(git rev-parse --abbrev-ref HEAD)"
  printf '  HEAD:   %s\n' "$(git log --oneline -1)"
  if git rev-parse -q --verify origin/main >/dev/null; then
    printf '  vs origin/main: %s behind, %s ahead\n' \
      "$(git rev-list --count HEAD..origin/main)" "$(git rev-list --count origin/main..HEAD)"
  fi
  if [ -z "$(git status --porcelain)" ]; then
    ok "working tree clean"
  else
    warn "uncommitted changes:"
    git status --short | head -10 | sed 's/^/        /'
  fi

  say "GitHub ($REPO_SLUG)"
  if have gh && gh api rate_limit >/dev/null 2>&1; then
    ok "gh can reach the GitHub API"
    printf '  open pull requests: %s\n' "$(gh api "repos/$REPO_SLUG/pulls?state=open" --jq 'length' 2>/dev/null || echo '?')"
    gh api "repos/$REPO_SLUG/pulls?state=open" --jq '.[] | "    #\(.number) \(.title) (\(.user.login))"' 2>/dev/null | head -15 || true
    sha="$(gh api "repos/$REPO_SLUG/commits/main" --jq .sha 2>/dev/null || true)"
    if [ -n "$sha" ]; then
      printf '  CI on main (%s): ' "${sha:0:8}"
      gh api "repos/$REPO_SLUG/commits/$sha/check-runs" --paginate --jq \
        '[.check_runs[]|.conclusion // .status] | group_by(.) | map("\(.[0])=\(length)") | join("  ")' 2>/dev/null | tr '\n' ' ' || true
      echo
    fi
    printf '  nightly stress run: '
    gh api "repos/$REPO_SLUG/actions/workflows/stress-test.yml/runs?per_page=1" \
      --jq 'if (.workflow_runs|length)==0 then "no run yet (trigger: gh workflow run stress-test.yml)" else .workflow_runs[0]|"\(.status) \(.conclusion // "-") \(.created_at)" end' 2>/dev/null || echo "?"
    alerts="$(gh api "repos/$REPO_SLUG/dependabot/alerts?state=open&per_page=100" --jq 'length' 2>/dev/null || true)"
    case "$alerts" in
      ''|*[!0-9]*) warn "Dependabot security alerts are disabled or not visible (Settings > Code security > Dependabot alerts)" ;;
      *) printf '  Dependabot alerts (open): %s\n' "$alerts" ;;
    esac
  else
    warn "gh missing or cannot reach GitHub (in Codespaces gh is pre-authenticated; else: gh auth login)"
  fi

  say "toolchain"
  for t in python3 pip node npm psql ruff; do
    if have "$t"; then printf '  %-8s %s\n' "$t" "$("$t" --version 2>&1 | head -1)"; else warn "$t missing"; fi
  done
  if [ -d node_modules ]; then ok "node_modules present"; else warn "node_modules missing -> setup"; fi
  if python3 -c "import assurance, neuralbridge" 2>/dev/null; then
    ok "python package importable"
  else
    warn "package not installed -> setup"
  fi

  say "PostgreSQL (needed so the /ai tests and the browser suite run instead of skipping)"
  if pg_up; then ok "accepting connections on $PG_HOST:$PG_PORT"; else warn "not running -> setup"; fi
  [ "$FAILED" = 0 ]
}

cmd_setup() {
  say "python"
  python3 -m pip install -q --require-hashes --no-deps -r requirements/test.lock
  python3 -m pip install -q --no-deps -e .
  python3 -m pip check && ok "python dependencies consistent"

  say "node"
  npm ci --no-audit --no-fund --ignore-scripts && ok "npm ci"

  say "browser"
  if [ -n "${PLAYWRIGHT_CHROMIUM_PATH:-}" ] || ls /opt/pw-browsers >/dev/null 2>&1; then
    ok "a browser is pre-installed; not downloading one"
  else
    npx playwright install --with-deps chromium
  fi

  say "postgresql"
  if pg_up; then
    ok "already running"
  else
    SUDO=""; [ "$(id -u)" = 0 ] || SUDO="sudo"
    if ! find /usr/lib/postgresql -name initdb 2>/dev/null | grep -q .; then
      $SUDO apt-get update -q && $SUDO apt-get install -y -q postgresql postgresql-client
    fi
    BIN="$(find /usr/lib/postgresql -mindepth 2 -maxdepth 2 -name bin | sort -V | tail -1)"
    mkdir -p "$PG_DIR"
    if [ "$(id -u)" = 0 ]; then
      # postgres refuses to run as root; use its own unprivileged user and a directory it owns.
      PG_DIR=/var/lib/nb-pg-test; mkdir -p "$PG_DIR"; chown postgres:postgres "$PG_DIR"; chmod 700 "$PG_DIR"
      RUN="su postgres -c"
    else
      RUN="bash -c"
    fi
    [ -d "$PG_DIR/data" ] || $RUN "$BIN/initdb -D $PG_DIR/data -A trust -U postgres >/dev/null"
    $RUN "$BIN/pg_ctl -D $PG_DIR/data -o '-p $PG_PORT -k $PG_DIR' -l $PG_DIR/log start -w >/dev/null"
    ok "started a local PostgreSQL in $PG_DIR (loopback only, no remote access)"
  fi
  PSQL="psql -h $PG_HOST -p $PG_PORT -U postgres -qtA"
  $PSQL -c "SELECT 1 FROM pg_roles WHERE rolname='$PG_USER'" | grep -q 1 \
    || $PSQL -c "CREATE ROLE $PG_USER LOGIN SUPERUSER PASSWORD '$PG_PASS'"
  for db in "$PG_DB_TEST" "$PG_DB_E2E"; do
    $PSQL -c "SELECT 1 FROM pg_database WHERE datname='$db'" | grep -q 1 \
      || $PSQL -c "CREATE DATABASE $db OWNER $PG_USER"
  done
  ok "role $PG_USER and databases $PG_DB_TEST, $PG_DB_E2E ready"
}

cmd_verify() {
  pg_up || { bad "PostgreSQL is not running; run: bash scripts/codespaces.sh setup"; return 1; }
  pg_env
  say "ruff";          ruff check src/ tests/ && ok "ruff clean"
  say "capabilities";  python3 -m assurance capabilities --check
  say "pytest (Postgres and Node REQUIRED; this takes ~20 minutes)"
  local junit; junit="$(mktemp --suffix=.xml)"
  python3 -m pytest tests -q --no-cov -p no:cacheprovider -rfE --junitxml="$junit"
  python3 scripts/check_test_skips.py "$junit"
  say "site"
  npx tsc --noEmit && ok "tsc"
  npm run build >/dev/null && ok "next build"
}

cmd_e2e() {
  pg_up || { bad "PostgreSQL is not running; run: bash scripts/codespaces.sh setup"; return 1; }
  pg_env "$PG_DB_E2E"
  export CI=true PYTHON=python3
  if [ -z "${PLAYWRIGHT_CHROMIUM_PATH:-}" ] && [ -d /opt/pw-browsers ]; then
    PLAYWRIGHT_CHROMIUM_PATH="$(find /opt/pw-browsers -path "*/chromium-*/chrome-linux*/chrome" -type f 2>/dev/null | head -1 || true)"
    export PLAYWRIGHT_CHROMIUM_PATH PLAYWRIGHT_BROWSERS_PATH=/opt/pw-browsers
  fi
  bash scripts/e2e-local.sh
}

cmd_stress() {
  if [ ! -d "$STRESS_DIR/.git" ]; then
    GIT_LFS_SKIP_SMUDGE=1 git clone --depth 1 "https://github.com/$STRESS_SLUG" "$STRESS_DIR"
  else
    git -C "$STRESS_DIR" pull -q --ff-only || warn "could not update the stress-test checkout"
  fi
  python3 -m pip install -q "pytest>=8.3,<9" "cryptography>=42"
  ( cd "$STRESS_DIR" && NEURALBRIDGE_SRC="$ROOT/src" python3 -m pytest -q -rfEX --no-header )
}

cmd_ci() {
  have gh || { bad "gh is required"; return 1; }
  if [ -n "${1:-}" ]; then
    gh pr checks "$1" --repo "$REPO_SLUG" --watch
  else
    gh run list --repo "$REPO_SLUG" --branch main --limit 10
  fi
}

case "${1:-}" in
  status) cmd_status ;;
  setup)  cmd_setup ;;
  verify) cmd_verify ;;
  e2e)    cmd_e2e ;;
  stress) cmd_stress ;;
  ci)     shift; cmd_ci "$@" ;;
  all)    cmd_status || true; cmd_setup; cmd_verify; cmd_e2e; cmd_stress ;;
  *)      sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
exit "$FAILED"
