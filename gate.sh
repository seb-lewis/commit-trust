#!/bin/bash
# commit-trust composite-action entry point. Builds a throwaway partial clone (commits + trees, blobs on
# demand) holding only what this event needs, runs `commit_trust.py gha` on it, then deletes it. Nothing
# from the repository is checked out or executed. Runs before actions/checkout, so it can't be influenced
# by files in the workspace.
set -uo pipefail
: "${GITHUB_REPOSITORY:?}" "${GITHUB_EVENT_PATH:?}" "${GITHUB_SHA:?}"
here="${GITHUB_ACTION_PATH:-$(cd "$(dirname "$0")" && pwd)}"
mode="${CT_MODE:-enforce}"
dir="${RUNNER_TEMP:-/tmp}/commit-trust-$$"
trap 'rm -rf "$dir" "$dir.state" "$dir.out" "$dir.err"' EXIT
command -v python3 >/dev/null || { echo "::error title=commit-trust::python3 is required on the runner"; exit 1; }

gitc() { git -C "$dir" -c core.hooksPath=/dev/null -c core.fsmonitor=false -c protocol.file.allow=never "$@"; }
git init -q --bare "$dir"
gitc remote add origin "${GITHUB_SERVER_URL:-https://github.com}/$GITHUB_REPOSITORY.git"
gitc config remote.origin.promisor true
gitc config remote.origin.partialclonefilter blob:none
if [ -n "${CT_TOKEN:-}" ]; then
  # Same mechanism actions/checkout uses; lives only in this temp repo's config and is deleted on exit.
  gitc config http.extraheader "AUTHORIZATION: basic $(printf 'x-access-token:%s' "$CT_TOKEN" | base64 | tr -d '\n')"
fi

default=$(python3 -I -c 'import json,os;e=json.load(open(os.environ["GITHUB_EVENT_PATH"]));print((e.get("repository") or {}).get("default_branch") or "main")')
want=$(python3 -I -c '
import json, os
e = json.load(open(os.environ["GITHUB_EVENT_PATH"]))
shas = [os.environ["GITHUB_SHA"]]
pr = e.get("pull_request") or {}
for s in ((pr.get("head") or {}).get("sha"), (pr.get("base") or {}).get("sha"), e.get("before")):
    if s and s != "0" * 40:
        shas.append(s)
print(" ".join(dict.fromkeys(shas)))')

# Default branch history (for merge-base) plus the event's commits. Blobs are fetched lazily, only for diffs.
if ! gitc fetch -q --no-tags --filter=blob:none origin "+refs/heads/$default:refs/remotes/origin/$default" $want 2>"$dir.err"; then
  # A force-push's "before" may no longer exist; retry without it.
  gitc fetch -q --no-tags --filter=blob:none origin "+refs/heads/$default:refs/remotes/origin/$default" "$GITHUB_SHA" ||
    { echo "::error title=commit-trust::could not fetch commits: $(head -c 300 "$dir.err")"; rm -f "$dir.err"; exit 1; }
fi
rm -f "$dir.err"

mkdir -p "$dir.state"
for s in $(echo "${CT_APPROVED:-}" | tr ',' ' '); do
  [[ "$s" =~ ^[0-9a-f]{40}$ ]] || { echo "::warning title=commit-trust::ignoring approved entry that isn't a full SHA"; continue; }
  printf '{"repo":"%s","sha":"%s","reason":"actions variable"}\n' "$GITHUB_REPOSITORY" "$s" >> "$dir.state/approved.jsonl"
done
out="$dir.out"
GH_TOKEN="${CT_TOKEN:-}" COMMIT_TRUST_STATE="$dir.state" python3 -I "$here/commit_trust.py" gha --repo "$dir" | tee "$out"
rc=${PIPESTATUS[0]}
rm -rf "$dir.state"
verdict=$(grep -oE '^(PASS|WARN|FAIL): ' "$out" | tail -1 | tr -d ': '); rm -f "$out"
[ -n "${GITHUB_OUTPUT:-}" ] && echo "verdict=${verdict:-ERROR}" >> "$GITHUB_OUTPUT"
case $rc in
  0) exit 0 ;;
  2) if [ "$mode" = warn ]; then echo "::warning title=commit-trust::FAIL findings (mode=warn, not blocking)"; exit 0; fi
     echo "::error title=commit-trust::Suspicious commits. Nothing from them should run. Review the findings above; after a human review the owner can approve on the host: commit-trust approve $GITHUB_REPOSITORY <sha> --reason ..."
     exit 1 ;;
  *) echo "::error title=commit-trust::check errored (exit $rc); failing closed"; exit 1 ;;
esac
