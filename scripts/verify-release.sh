#!/usr/bin/env bash
# Verify a published release image the way an outsider would, against a DIGEST. Fails closed.
#
#   scripts/verify-release.sh --image ghcr.io/OWNER/REPO[-assurance] --digest sha256:<64 hex> \
#       [--repo OWNER/REPO] [--ref refs/tags/vX.Y.Z] [--sbom-out FILE]
#
# It checks three independent things for exactly that digest, and passes only if all three do:
#   1. a keyless cosign signature whose certificate names THIS repository's publish-docker.yml
#      workflow (at --ref, or at any refs/tags/v* when --ref is not given), issued by GitHub
#      Actions' OIDC issuer;
#   2. a GitHub build-provenance attestation (SLSA provenance v1) for the digest, signed by that
#      same workflow;
#   3. a GitHub SBOM attestation (CycloneDX) for the digest, signed by that same workflow.
# Every verified statement must also name the digest you asked about: a tool exit code of 0 for
# some OTHER digest is a failure here.
#
# Exit: 0 all three verified | 1 something was checked and did not verify | 2 could not check
# (missing tool, bad arguments, no network). 2 is NOT a pass.
#
# Needs: cosign (>= 2), gh (>= 2.50, logged in or GH_TOKEN set: `gh attestation verify` calls the
# GitHub API), python3. Reaches the registry, Sigstore's public-good TUF/Rekor and api.github.com.
# Reads no secret; GH_TOKEN, if present, is used only by gh.
#
# What a pass means: the registry bytes at this digest were built and signed by that workflow in
# that repository. It does not mean the code is free of defects, that the dependencies are benign,
# or that the SBOM describes OS packages (it is derived from the lock file). It does not prove the
# repository itself was not compromised. Redeploy by digest.
#
# STATUS: written and exercised against stub cosign/gh binaries (tests/test_verify_release.py).
# It has NOT been run against a real signed image: no release workflow has run yet.

set -uo pipefail

ISSUER="https://token.actions.githubusercontent.com"
WORKFLOW_FILE="publish-docker.yml"

usage() {
  sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//' >&2
}
die_unchecked() { echo "UNCHECKED: $*" >&2; exit 2; }
fail() { echo "FAIL: $*" >&2; exit 1; }

IMAGE="" DIGEST="" REPO="" REF="" SBOM_OUT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --image)    [ $# -ge 2 ] || die_unchecked "--image needs a value"; IMAGE="$2"; shift 2 ;;
    --digest)   [ $# -ge 2 ] || die_unchecked "--digest needs a value"; DIGEST="$2"; shift 2 ;;
    --repo)     [ $# -ge 2 ] || die_unchecked "--repo needs a value"; REPO="$2"; shift 2 ;;
    --ref)      [ $# -ge 2 ] || die_unchecked "--ref needs a value"; REF="$2"; shift 2 ;;
    --sbom-out) [ $# -ge 2 ] || die_unchecked "--sbom-out needs a value"; SBOM_OUT="$2"; shift 2 ;;
    -h|--help)  usage; exit 0 ;;
    *) die_unchecked "unknown argument: $1" ;;
  esac
done

[ -n "$IMAGE" ]  || die_unchecked "--image is required"
[ -n "$DIGEST" ] || die_unchecked "--digest is required (verify a digest, never a tag)"
# Strict shapes: nothing that reaches a command line or a regexp below may contain anything else.
[[ "$DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]] || die_unchecked "digest must look like sha256:<64 lower-case hex>"
[[ "$IMAGE" =~ ^ghcr\.io/[a-z0-9._-]+/[a-z0-9._/-]+$ ]] \
  || die_unchecked "image must be a lower-case ghcr.io/OWNER/NAME reference without tag or digest"
case "$IMAGE" in *@*|*:*:*) die_unchecked "image must not carry a tag or digest; pass --digest" ;; esac
if [ -z "$REPO" ]; then
  # ghcr.io/OWNER/REPO[-assurance] -> OWNER/REPO
  rest="${IMAGE#ghcr.io/}"; owner="${rest%%/*}"; name="${rest#*/}"; name="${name%-assurance}"
  REPO="${owner}/${name}"
fi
[[ "$REPO" =~ ^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$ ]] || die_unchecked "--repo must be OWNER/REPO"
if [ -n "$REF" ]; then
  [[ "$REF" =~ ^refs/(tags|heads)/[A-Za-z0-9._/-]+$ ]] || die_unchecked "--ref must be refs/tags/... or refs/heads/..."
fi

command -v cosign  >/dev/null 2>&1 || die_unchecked "cosign is not installed"
command -v gh      >/dev/null 2>&1 || die_unchecked "gh is not installed"
command -v python3 >/dev/null 2>&1 || die_unchecked "python3 is not installed"

# Identity the certificate must carry. Exact when --ref is given; otherwise any version tag.
# (?i): the image name is lower case, the repository name in the certificate keeps its case.
re_escape() { printf '%s' "$1" | sed 's#[][\.^$*+?(){}|]#\\&#g'; }
if [ -n "$REF" ]; then
  ID_RE="(?i)^https://github\\.com/$(re_escape "$REPO")/\\.github/workflows/$(re_escape "$WORKFLOW_FILE")@$(re_escape "$REF")\$"
else
  ID_RE="(?i)^https://github\\.com/$(re_escape "$REPO")/\\.github/workflows/$(re_escape "$WORKFLOW_FILE")@refs/tags/v[A-Za-z0-9._-]+\$"
fi
SIGNER_WORKFLOW="${REPO}/.github/workflows/${WORKFLOW_FILE}"
SUBJECT="${IMAGE}@${DIGEST}"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/verify-release.XXXXXX")" || die_unchecked "no temp directory"
trap 'rm -rf "$WORK"' EXIT

# ---- 1. cosign signature -------------------------------------------------------------------
echo "== 1/3 cosign signature for ${SUBJECT}" >&2
if ! cosign verify \
      --certificate-identity-regexp "$ID_RE" \
      --certificate-oidc-issuer "$ISSUER" \
      "$SUBJECT" >"$WORK/cosign.json" 2>"$WORK/cosign.err"; then
  sed 's/^/  cosign: /' "$WORK/cosign.err" >&2
  fail "no valid cosign signature by ${SIGNER_WORKFLOW} for ${SUBJECT}"
fi
# cosign prints a JSON array of signed payloads. Every one it returns must be about our digest,
# and there must be at least one.
python3 - "$WORK/cosign.json" "$DIGEST" <<'PY' || fail "cosign accepted a signature, but not for the requested digest"
import json, sys
path, want = sys.argv[1], sys.argv[2]
try:
    payloads = json.load(open(path))
except Exception:
    sys.exit(1)
if not isinstance(payloads, list) or not payloads:
    sys.exit(1)
for p in payloads:
    got = (((p or {}).get("critical") or {}).get("image") or {}).get("docker-manifest-digest")
    if got != want:
        sys.exit(1)
PY
echo "   ok" >&2

# ---- 2 and 3. GitHub attestations ----------------------------------------------------------
check_attestation() {
  local label="$1" ptype="$2" out="$3"
  echo "== ${label} (${ptype})" >&2
  if ! gh attestation verify "oci://${SUBJECT}" \
        --repo "$REPO" \
        --signer-workflow "$SIGNER_WORKFLOW" \
        --predicate-type "$ptype" \
        --format json >"$out" 2>"$WORK/gh.err"; then
    sed 's/^/  gh: /' "$WORK/gh.err" >&2
    fail "no valid ${label} attestation for ${SUBJECT} from ${SIGNER_WORKFLOW}"
  fi
  python3 - "$out" "$DIGEST" "$ptype" <<'PY' || fail "${label} verified, but not for the requested digest and predicate type"
import json, sys
path, want, ptype = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    results = json.load(open(path))
except Exception:
    sys.exit(1)
if not isinstance(results, list) or not results:
    sys.exit(1)
hexd = want.split(":", 1)[1]
for r in results:
    stmt = (((r or {}).get("verificationResult") or {}).get("statement")) or {}
    subjects = stmt.get("subject") or []
    if stmt.get("predicateType") != ptype:
        sys.exit(1)
    if not any((s.get("digest") or {}).get("sha256") == hexd for s in subjects):
        sys.exit(1)
PY
  echo "   ok" >&2
}

check_attestation "2/3 build provenance" "https://slsa.dev/provenance/v1" "$WORK/provenance.json"
check_attestation "3/3 SBOM" "https://cyclonedx.org/bom" "$WORK/sbom-att.json"

if [ -n "$SBOM_OUT" ]; then
  python3 - "$WORK/sbom-att.json" "$SBOM_OUT" <<'PY' || fail "could not extract the attested SBOM"
import json, sys
results = json.load(open(sys.argv[1]))
pred = results[0]["verificationResult"]["statement"]["predicate"]
with open(sys.argv[2], "w") as fh:
    json.dump(pred, fh, indent=2, sort_keys=True)
PY
  echo "   attested SBOM written to ${SBOM_OUT}" >&2
fi

echo "VERIFIED ${SUBJECT}: signature, provenance and SBOM attestation all name this digest and ${SIGNER_WORKFLOW}." >&2
exit 0
