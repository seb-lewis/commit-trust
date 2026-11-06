# commit-trust

A read-only gate that decides whether commits are safe to **merge** or to **run in CI**. It's built for the case where most commits are unsigned and "is it signed?" doesn't tell you enough.

It came out of a real supply-chain attack. The attacker pushed unsigned commits that copied real commit messages, authors and timestamps, and hid loaders in build configs, editor tasks and fake asset files. commit-trust looks for exactly those traits.

It never runs anything it inspects:
- It only uses git plumbing (`rev-list`, `diff-tree`, `cat-file`) and, optionally, `gh api`.
- It never checks out, installs, builds or executes repository code.
- Every git call disables hooks, fsmonitor, external diff and textconv.

## Install

Requires `python3` (3.8+) and `git`. `gh` is optional; it adds GitHub signature and PR-merge lookups.

```sh
curl -fsSLO https://github.com/seb-lewis/commit-trust/releases/latest/download/install.sh
less install.sh          # read it first
sh install.sh            # installs to ~/.local/bin/commit-trust (no sudo); PREFIX=... to change
commit-trust --version
```

`install.sh` downloads the release's `commit_trust.py` and checks it against the SHA-256 baked into the script. If they don't match, it refuses to install. Each release's checksums are also listed in its notes and in `SHA256SUMS`.

## Use it before you merge or run anything

```sh
commit-trust gate                        # HEAD vs origin's default branch (fetches first)
commit-trust gate origin/feature-x       # before merging / rebasing onto / checking out a branch
commit-trust gate --pr OWNER/REPO#123    # a PR, without checking it out
```

| Exit | Output | Meaning |
|---|---|---|
| `0` | `GATE: PASS` | Proceed. Unsigned but clean commits pass, and WARN items are listed for information |
| `1` | `GATE: BLOCKED` | FAIL findings, or the check couldn't run. Don't merge, build or run it |

Other commands:
- `check` / `pr`: the full report, with verdicts `0` PASS, `1` WARN, `2` FAIL. `-v` adds details and `--json` gives JSON.
- `approve OWNER/REPO SHA --reason "..."`: records a human review on this machine only, so nothing in a repo can approve itself.

## Use it as the first step of every CI job

```yaml
jobs:
  build:
    runs-on: ubuntu-latest           # or your self-hosted labels
    steps:
      - uses: seb-lewis/commit-trust@<commit-sha>   # FIRST, before checkout or any script; pin by SHA
        with:
          approved: ${{ vars.COMMIT_TRUST_APPROVED }}   # optional: full SHAs a human reviewed
          config: ${{ vars.COMMIT_TRUST_CONFIG }}       # optional: inline JSON config (below)
      - uses: actions/checkout@<sha>
      - run: make test
```

How the step works:
- **No checkout needed.** It builds a throwaway partial clone in `$RUNNER_TEMP`, checks exactly the commits this event brings in, and deletes the clone. That's `before..after` for a push, base through head for a PR, otherwise from the merge-base or the last 20 commits.
- **Speed:** a few seconds, even on large monorepos.
- **Failure:** a FAIL, or any error, fails the job (fail closed). `mode: warn` reports without blocking.
- **Output:** `outputs.verdict` holds PASS, WARN or FAIL, and the findings appear as annotations and a job summary.
- **Pinning:** reference it by commit SHA, and never vendor it into the repo it protects. A malicious commit could edit a vendored copy in the same push.
- **Best placement:** run it outside the job too, e.g. in whatever starts your self-hosted runners, before the runner exists. A commit can delete a step from its own workflow, but it can't remove a check that runs before the workflow does: `commit-trust ci --slug OWNER/REPO --sha SHA --ref BRANCH`.

## What it flags

**High severity (FAIL):**
- **Editor auto-run:** `.vscode/tasks.json` with `runOn: folderOpen`, `task.allowAutomaticTasks`, `.envrc`.
- **Git hooks:** husky, lefthook, pre-commit, `core.hooksPath` pointed anywhere but `/dev/null`.
- **Hidden code:** code placed after a long run of spaces, past the right edge of the editor.
- **Obfuscated JavaScript:** `_0x…` identifiers, the not-not-empty-array loop idiom, hex string decoders, `$`-mangled names, char-code payloads, and a known `global['!']` loader signature.
- **Disguised files:**
  - code inside font, image or odd-extension files
  - assets whose bytes don't match their type
  - extensionless loader scripts
  - SVGs containing a script
- **package.json:**
  - scripts that run an extensionless or odd-extension file, such as `node init && …`
  - install scripts that download or eval
  - dependencies installed straight from URLs or git
- **Build configs:** a build or tool config (vite, svelte, postcss, playwright and similar) that gains `child_process`, eval, spawn or a dynamic require.
- **Package managers:** lockfile entries resolved from unusual hosts; package-manager config that re-enables install scripts or switches registry.
- **Workflows:** `pull_request_target`, `toJSON(secrets)`, secrets sent over the network.
- **Network and payloads:** hard-coded public-IP URLs, eval of decoded data, detached child processes, encoded PowerShell.
- **Metadata:**
  - **Replayed metadata:** an unsigned commit whose subject claims to be PR #N, while PR #N actually merged as a different commit with different content.
  - an invalid signature

**Medium severity (WARN):**
- whole-file rewrites (line-ending or indent changes that bury a small edit)
- any workflow change, and untrusted event text expanded inside workflows
- new lifecycle scripts, and `trustedDependencies` / `onlyBuiltDependencies` changes
- `.gitignore` no longer ignoring `.env`
- devcontainer commands
- very long lines
- identity, name or timezone mismatches, once you've configured them

**Applies to every commit, signed or not.** GitHub signs commits made through its web UI and API, so a stolen token can still produce "Verified" commits.

## Config

Optional. Use `~/.config/commit-trust/config.json`, or inline JSON in `COMMIT_TRUST_CONFIG_JSON` (the action's `config` input):

```json
{
  "identities": {"you@example.com": ["Your Name"]},
  "github_signed_only": ["noreply@github.com", "12345+you@users.noreply.github.com"],
  "allowed_tz": ["-0800", "-0700", "+0000"],
  "trusted_signers": ["your-github-login"]
}
```

- `identities`: committer emails, with the names expected to appear on unsigned commits.
- `github_signed_only`: identities that should only ever appear on GitHub-signed commits. An unsigned commit using one of them is flagged.
- `allowed_tz`: committer UTC offsets you actually use. Leave it empty to turn the timezone rule off.
- `trusted_signers`: GitHub logins whose signatures count as trusted.

## Range and caching
- **Branches and PRs:** commits that aren't on the default branch.
- **Default branch:** everything since the last cleared or approved commit.
  - The first scan covers the newest 200 commits. Anything older is accepted as the baseline.
- **Caching:** a commit is cached as cleared only if it, and everything below it in the range, has no FAIL. A clean commit on top can't hide a bad one.
- **State:** stored under `~/.local/state/commit-trust`.

## Limits
- It's a heuristic filter. It catches this attack family and common variants.
- A small, cleanly written malicious change will be a WARN at most. PASS means "nothing suspicious found", not "reviewed".
- Only the newest 200 commits are scanned on first contact.
