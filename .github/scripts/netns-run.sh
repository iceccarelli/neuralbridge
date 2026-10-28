#!/usr/bin/env bash
# Run a command inside a new network namespace that has no interface.
#
#   .github/scripts/netns-run.sh python -m assurance kit run kit.json --out out
#
# This is the enforced half of the offline kit's claim: the in-process airgap guard
# records whether the tool *tried* to reach a network; a namespace with no interface
# makes it *unable* to. It fails closed: when no namespace can be created the exit
# status is 97 and nothing runs, so a runner that cannot enforce the claim is red,
# never silently green.
#
# Tried in order:
#   1. an unprivileged user namespace:  unshare -rn
#   2. root creates the namespace and the command drops back to the calling user:
#        sudo unshare -n setpriv --reuid ... (GitHub-hosted Ubuntu images that restrict
#        unprivileged user namespaces, e.g. 24.04 with AppArmor, but allow sudo)
set -euo pipefail

if [ "$#" -eq 0 ]; then
  echo "usage: netns-run.sh COMMAND [ARG...]" >&2
  exit 2
fi

if command -v unshare >/dev/null 2>&1 && unshare -rn true 2>/dev/null; then
  exec unshare -rn "$@"
fi

if command -v unshare >/dev/null 2>&1 && command -v setpriv >/dev/null 2>&1 \
    && sudo -n unshare -n true 2>/dev/null; then
  # sudo resets PATH to its secure_path even with -E, so a bare `python` would be the system
  # interpreter, not the caller's (setup-python's). Resolve the command here, before sudo.
  cmd="$(command -v -- "$1")" || { echo "netns-run: command not found: $1" >&2; exit 127; }
  shift
  exec sudo -n -E unshare -n setpriv --reuid="$(id -u)" --regid="$(id -g)" \
    --clear-groups "$cmd" "$@"
fi

echo "netns-run: cannot create a network namespace here (tried 'unshare -rn' and" >&2
echo "netns-run: 'sudo unshare -n'). The offline kit's claim would be unenforced." >&2
exit 97
