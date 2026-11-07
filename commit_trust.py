#!/usr/bin/env python3
"""commit-trust: decide whether commits (especially unsigned ones) are safe to merge or to run CI on.

Read-only. It only ever runs git plumbing (rev-list, show, diff-tree, cat-file) and `gh api`. It never
checks out, builds, installs, or executes anything from the repository, and it disables repo-level
hooks, fsmonitor, external diff and textconv drivers on every git call.

Commands
  check [REV] [--base REF ...] [--repo PATH]    review commits in REV that aren't in the base (default: origin default branch)
  pr OWNER/REPO NUMBER                           review a PR's commits (fetched into a bare cache; nothing checked out)
  ci --slug OWNER/REPO --sha SHA [--ref BRANCH] [--event EVENT] [--status]
                                                 CI gate used by the runner supervisor before a VM starts
  approve OWNER/REPO SHA --reason TEXT           mark a commit as manually reviewed (stored on this machine only)

Exit codes: 0 PASS, 1 WARN (unsigned or needs a look, nothing malicious-looking), 2 FAIL (red flags), 3 error.
"""
import argparse, datetime, json, os, re, subprocess, sys

VERSION = "1.4.7"
HOME = os.path.expanduser("~")
CONFIG_PATH = os.environ.get("COMMIT_TRUST_CONFIG", os.path.join(HOME, ".config/commit-trust/config.json"))
STATE = os.environ.get("COMMIT_TRUST_STATE", os.path.join(HOME, ".local/state/commit-trust"))
MAX_COMMITS = 200

# Generic defaults. Put your own identities, timezones and signers in ~/.config/commit-trust/config.json
# (or pass inline JSON in COMMIT_TRUST_CONFIG_JSON, e.g. from a repo/org Actions variable).
# Empty lists/maps switch the matching identity/timezone rule off rather than flagging everything.
DEFAULT_CONFIG = {
    # Unsigned commits are expected from these committer identities (email -> allowed names).
    "identities": {
        "41898282+github-actions[bot]@users.noreply.github.com": ["github-actions[bot]"],
    },
    # Identities that are only legitimate on GitHub-signed commits (web merges / squash merges).
    # Add your own <id>+<login>@users.noreply.github.com if you never commit locally with it.
    "github_signed_only": ["noreply@github.com"],
    # Committer UTC offsets seen on legitimate commits, e.g. ["-0800", "-0700", "+0000"].
    "allowed_tz": [],
    # GitHub logins whose own signatures are trusted.
    "trusted_signers": [],
    # Hex-encoded (decoded at load) so this detector's own source doesn't contain the indicators it hunts for.
    "ioc_hex": ["39352e3133352e3138312e313531", "2e6e706d2d7773", "2f30782f636c73", "6e706d2d77732d72756e6e6572", "5f745f73223a2268747470"],
    "ioc_strings": [],
}

SEV_ORDER = {"high": 3, "medium": 2, "low": 1, "info": 0}

# ---------------------------------------------------------------- utilities

def load_config():
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    sources = []
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH) as f:
            sources.append(json.load(f))
    if os.environ.get("COMMIT_TRUST_CONFIG_JSON", "").strip():
        sources.append(json.loads(os.environ["COMMIT_TRUST_CONFIG_JSON"]))
    for user in sources:
        if user.get("identities"):
            cfg["_identities_set"] = True
        for k, v in user.items():
            if isinstance(v, dict) and isinstance(cfg.get(k), dict):
                cfg[k].update(v)
            else:
                cfg[k] = v
    return cfg

SAFE_GIT = ["-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-c", "diff.external=",
            "-c", "core.pager=cat", "-c", "protocol.file.allow=never", "-c", "submodule.recurse=false"]

class GitError(Exception):
    pass

def git(repo, *args, check=True, binary=False, inp=None):
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_OPTIONAL_LOCKS="0", GIT_EXTERNAL_DIFF="", LC_ALL="C")
    p = subprocess.run(["git", "-C", repo] + SAFE_GIT + list(args), capture_output=True, env=env, input=inp)
    if check and p.returncode != 0:
        raise GitError("git %s: %s" % (" ".join(args[:3]), p.stderr.decode(errors="replace").strip()[:300]))
    return p.stdout if binary else p.stdout.decode("utf-8", errors="replace")

def gh(*args, check=True):
    try:
        p = subprocess.run(["gh"] + list(args), capture_output=True, text=True)
    except OSError as e:  # gh not installed (e.g. inside a CI VM without it)
        raise RuntimeError("gh unavailable: %s" % e)
    if check and p.returncode != 0:
        raise RuntimeError("gh %s: %s" % (" ".join(args[:2]), p.stderr.strip()[:300]))
    return p.stdout

TOKEN_RE = re.compile(r"(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{16,}|xox[abprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----|eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,})")

def snip(s, n=90):
    s = TOKEN_RE.sub("<redacted>", s)
    s = "".join(c if 32 <= ord(c) < 127 else "?" for c in s.strip())
    return s if len(s) <= n else s[:n] + "..."

def ensure_dir(p):
    os.makedirs(p, exist_ok=True)
    return p

# ---------------------------------------------------------------- state (approvals, cached verdicts)

def approvals(slug):
    path = os.path.join(STATE, "approved.jsonl")
    out = set()
    if os.path.exists(path):
        with open(path) as f:
            for line in f:
                try:
                    e = json.loads(line)
                except ValueError:
                    continue
                if e.get("repo") in (slug, "*"):
                    out.add(e["sha"])
    return out

def verdict_cache_path(slug):
    return os.path.join(ensure_dir(os.path.join(STATE, "commits")), (slug or "local").replace("/", "__") + ".json")

def load_commit_cache(slug):
    try:
        with open(verdict_cache_path(slug)) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}

def save_commit_cache(slug, cache):
    tmp = verdict_cache_path(slug) + ".tmp"
    with open(tmp, "w") as f:
        json.dump(cache, f)
    os.replace(tmp, verdict_cache_path(slug))

# ---------------------------------------------------------------- file classification

CODE_EXT = {".js", ".cjs", ".mjs", ".jsx", ".ts", ".cts", ".mts", ".tsx", ".svelte", ".vue", ".astro", ".py",
            ".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd", ".rb", ".pl", ".php", ".go", ".rs", ".cs", ".java", ".kt"}
DOC_EXT = {".md", ".mdx", ".rst", ".txt", ".adoc"}
TEXTISH_NONCODE = {".md", ".mdx", ".txt", ".csv", ".json", ".yml", ".yaml", ".toml", ".lock", ".html", ".css",
                   ".scss", ".xml", ".sql", ".graphql", ".env", ".ini", ".cfg", ".conf", ".rst", ".snap", ".map",
                   ".patch", ".diff", ".log", ".jsonl", ".ndjson", ".tsv", ".http", ".har", ".txtar", ".j2", ".tmpl", ".hbs", ".ejs"}
MAGIC = {
    ".woff": [b"wOFF"], ".woff2": [b"wOF2"], ".ttf": [b"\x00\x01\x00\x00", b"true", b"OTTO"], ".otf": [b"OTTO", b"\x00\x01\x00\x00"],
    ".png": [b"\x89PNG"], ".jpg": [b"\xff\xd8\xff"], ".jpeg": [b"\xff\xd8\xff"], ".gif": [b"GIF8"], ".webp": [b"RIFF"],
    ".ico": [b"\x00\x00\x01\x00"], ".pdf": [b"%PDF"], ".zip": [b"PK"], ".gz": [b"\x1f\x8b"], ".wasm": [b"\x00asm"],
    ".mp4": [b"ftyp"], ".avif": [b"ftyp"],
}
KNOWN_EXTENSIONLESS = {"LICENSE", "LICENCE", "NOTICE", "COPYING", "AUTHORS", "CODEOWNERS", "Makefile", "Dockerfile",
                       "Containerfile", "Procfile", "Gemfile", "Brewfile", "Justfile", "justfile", "Rakefile", "Vagrantfile",
                       "VERSION", "CHANGELOG", "README", "OWNERS", "Caddyfile", "Tiltfile", "Pipfile"}
BUILD_CONFIG_RE = re.compile(r"(^|/)((svelte|vite|vitest|postcss|tailwind|next|nuxt|astro|webpack|rollup|babel|eslint|prettier|jest|playwright|metro|tsup|esbuild|remix|turbo|drizzle|stylelint|commitlint|lint-staged|unocss|panda)\.config\.(c|m)?(js|ts)|\.eslintrc\.(c)?js|\.babelrc\.js|\.prettierrc\.(c)?js|gulpfile\.(c|m)?js|Gruntfile\.js|\.pnpmfile\.cjs|\.yarnrc\.yml|\.mocharc\.(c)?js)$")
HOOK_PATH_RE = re.compile(r"(^|/)(\.husky/|\.githooks/|\.git-hooks/|lefthook(-local)?\.ya?ml$|\.lefthook/|\.pre-commit-config\.yaml$|\.simple-git-hooks)")
EDITOR_RE = re.compile(r"(^|/)(\.vscode/|\.idea/|\.devcontainer/|\.zed/|\.cursor/|\.envrc$|\.nvim\.lua$|\.exrc$|\.vimrc$)")
WORKFLOW_RE = re.compile(r"(^|/)(\.github/workflows/|\.github/actions/|action\.ya?ml$|\.gitlab-ci\.yml$|\.circleci/)")
PKG_CONFIG_RE = re.compile(r"(^|/)(\.npmrc|\.yarnrc|\.yarnrc\.yml|bunfig\.toml|pnpm-workspace\.yaml|\.pnpmfile\.cjs|pip\.conf|\.pypirc)$")
LOCKFILE_RE = re.compile(r"(^|/)(package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb?)$")
MINIFIED_OK_RE = re.compile(r"(\.min\.(js|css)$|(^|/)(dist|vendor|third_party|build|static/vendor)/|\.map$|\.snap$|\.svg$|\.lock$|-lock\.(json|yaml)$|\.lockb$|\.(json|csv|tsv|txt|html|xml|sql|pem|patch)$)")

LIFECYCLE = {"preinstall", "install", "postinstall", "prepare", "preprepare", "postprepare", "prepublish",
             "prepublishOnly", "prepack", "postpack", "preuninstall", "uninstall", "postuninstall", "dependencies"}

def ext_of(path):
    base = path.rsplit("/", 1)[-1]
    if "." not in base.lstrip("."):
        return ""
    return "." + base.rsplit(".", 1)[-1].lower()

def looks_like_code(text):
    t = text[:20000]
    hits = sum(1 for p in (r"\brequire\s*\(", r"\bfunction\s*\(", r"=>", r"\bimport\s+[\w{*]", r"\bvar\s+\w+\s*=", r"\bconst\s+\w+\s*=",
                            r"\bprocess\.(env|argv|cwd)", r"child_process", r"\beval\s*\(", r"^#!", r"\bdef\s+\w+\(", r"\bimport\s+\w+$")
               if re.search(p, t, re.M))
    return hits >= 2

# ---------------------------------------------------------------- content rules (applied to one commit)

OBF_PATTERNS = [
    (re.compile(r"_0x[0-9a-f]{4,}"), 5, "javascript-obfuscator identifiers (_0x....)"),
    (re.compile(r"while\s*\(\s*!!\s*\[\s*\]\s*\)"), 1, "obfuscator infinite-loop idiom (while not-not-empty-array)"),
    (re.compile(r"parseInt\(\s*0x[0-9a-f]+\s*\)"), 2, "hex-arithmetic string decoder"),
    (re.compile(r"\b[A-Za-z_]{2,}\$[A-Za-z_$]{2,}\$[A-Za-z_$]+"), 3, "$-mangled identifiers"),
    (re.compile(r"\\x[0-9a-fA-F]{2}"), 40, "dense \\x escapes"),
    (re.compile(r"String\.fromCharCode\((\s*\d+\s*,){8,}"), 1, "String.fromCharCode char-code payload"),
]
DANGER_PATTERNS = [
    (re.compile(r"(eval|new\s+Function|Function)\s*\(\s*(atob|Buffer\.from|decodeURIComponent|unescape|require\(['\"]zlib)"), "high", "eval of decoded data"),
    (re.compile(r"child_process['\"]?\)?[\s\S]{0,200}\b(detached\s*:\s*true|\.unref\(\))"), "high", "detached background child process"),
    (re.compile(r"require\(\s*['\"](child_process|node:child_process)['\"]\s*\)"), "low", "child_process import"),
    (re.compile(r"https?://(?!127\.|0\.0\.0\.0|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.)\d{1,3}(\.\d{1,3}){3}(?::\d+)?"), "high", "hard-coded public IP URL"),
    (re.compile(r"['\"](socket\.io-client|node-pty|keytar|clipboardy|systeminformation)['\"]"), "medium", "unusual dependency for app code"),
    (re.compile(r"(curl|wget)\s[^|\n]{0,200}\|\s*(sudo\s+)?(ba|z)?sh\b"), "medium", "pipes a download into a shell"),
    (re.compile(r"(Login Data|Local State|\.config/google-chrome|Library/Application Support/(Google|BraveSoftware)|logins\.json|key4\.db|\.ssh/id_|Keychains|\.aws/credentials|wallet\.dat|exodus|metamask)", re.I), "medium", "references browser/wallet/credential stores"),
    (re.compile(r"\bpowershell(\.exe)?\b[^\n]{0,80}\s-(e|ec|enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}|\[(System\.)?Convert\]::FromBase64String[^\n]{0,120}(iex|Invoke-Expression)", re.I), "high", "encoded PowerShell"),
    # Known first-stage loader family (BeaverTail-style): `global['!']='x-xxxx-x';var _$_1e42=...` hidden after spaces.
    (re.compile(r"global\[['\"]!['\"]\]\s*=\s*['\"][\d-]+['\"]|_\$_[0-9a-f]{4}\s*=\s*\(function"), "high", "known JS loader signature (global['!'] / _$_xxxx)"),
    (re.compile(r"\bcreateRequire\s*\(\s*import\.meta\.url\s*\)"), "low", "createRequire in ESM"),
]
HIDDEN_GAP_RE = re.compile(r"[^\s][ \t]{40,}[^\s]")
# What follows the gap: statements (punctuation or keywords) are what a hidden payload looks like.
HIDDEN_CODEY_RE = re.compile(r"[;{}()=]|\b(?:function|require|import|eval|var|let|const|new|return|await|exec|spawn)\b")
SQL_ALIGN_RE = re.compile(r"(?i)(?:AS|FROM|WHERE|AND|OR|ON|JOIN|LEFT|RIGHT|INNER|OUTER|THEN|ELSE|END|WHEN|CASE|DESC|ASC|"
                          r"NULLS?|NOT|IN|IS|LIKE|ILIKE|BY|GROUP|ORDER|HAVING|LIMIT|OFFSET|UNION|USING|RETURNING|SET|VALUES)\b"
                          r"(?:\s+(?:\"[^\"]*\"|[A-Za-z_][\w.]*|\*))?\s*,?\s*$")

# Decoders and execution sinks, JS/TS and Python. A loader decodes data and feeds the result to something that
# executes code or a shell command; the flow check below looks for that, not just both appearing in a file.
DECODER_RE = re.compile(
    r"Buffer\.from\([^)]{0,40000}?['\"](?:hex|base64|base64url|latin1|binary)['\"]"
    r"|\batob\s*\(|\bbytes\.fromhex\s*\(|\bbinascii\.(?:unhexlify|a2b_hex|a2b_base64)\s*\("
    r"|\bbase64\.(?:b64decode|b32decode|b16decode|a85decode|b85decode|urlsafe_b64decode|decodebytes)\s*\("
    r"|\bcodecs\.decode\s*\(|String\.fromCharCode\s*\(|\bparseInt\s*\([^)]{0,80},\s*16\s*\)"
    r"|\bzlib\.(?:inflate|inflateSync|gunzip|gunzipSync|decompress|brotliDecompress)\w*\s*\("
    r"|\bdecodeURIComponent\s*\(\s*escape\b")
# Calls that run their (string) argument as code or as a shell command.
EXEC_CALL_RE = re.compile(
    r"(?<![\w.$])eval\s*\(|\(\s*0\s*,\s*eval\s*\)\s*\(|\bnew\s+Function\s*\(|(?<![\w.$])Function\s*\("
    r"|\bvm\.(?:runIn\w+|compileFunction)\s*\(|\bnew\s+vm\.Script\s*\("
    r"|(?<![\w.$])(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\("
    r"|\bchild_process['\"]?\)?\.\w+\s*\(|\bsetTimeout\s*\(\s*(?![\s(]|function|async)|\bsetInterval\s*\(\s*(?![\s(]|function|async)"
    r"|(?<![\w.])(?:exec|compile)\s*\(|\bos\.(?:system|popen)\s*\(|\bsubprocess\.\w+\s*\(|\b__import__\s*\("
    r"|\b(?:marshal|pickle)\.loads\s*\(|\bimport\s*\(\s*['\"`]data:")
ASSIGN_RE = re.compile(r"([A-Za-z_$][\w$]*)\s*(?:\+=|=)(?!=)")
SINK_RE = re.compile(
    r"(?<![\w.$])eval\s*\(|\(\s*0\s*,\s*eval\s*\)|\bnew\s+Function\s*\(|(?<![\w.$])Function\s*\(\s*[^)\s]"
    r"|\bvm\.(?:runIn\w+|Script|compileFunction|SourceTextModule)\b|require\(\s*['\"](?:node:)?vm['\"]\s*\)"
    r"|\bchild_process\b|\b(?:exec|execSync|execFile|execFileSync|spawn|spawnSync|fork)\s*\("
    r"|\bimport\s*\(\s*['\"`]data:|\bsetTimeout\s*\(\s*['\"`]|\bsetInterval\s*\(\s*['\"`]"
    r"|(?:^|[^\w.])exec\s*\(|\bcompile\s*\([^)]{0,200}['\"]exec['\"]|\b__import__\s*\(|\bos\.system\s*\(|\bsubprocess\.\w+\s*\("
    r"|\bimportlib\.import_module\s*\(|\bctypes\b")
COMPUTED_GLOBAL_CALL_RE = re.compile(r"\b(?:globalThis|global|window|self|this)\s*\[\s*(?!['\"]\w+['\"]\s*\])[^\]]{1,80}\]\s*\(")
FRAGMENT_JOIN_RE = re.compile(r"\[\s*(?:['\"][^'\"\n]{1,6}['\"]\s*,\s*){1,15}['\"][^'\"\n]{1,6}['\"]\s*\]\s*\.join\s*\(\s*['\"]{2}\s*\)"
                              r"|(?:['\"][^'\"\n]{1,6}['\"]\s*\+\s*){1,15}['\"][^'\"\n]{1,6}['\"]")
DANGEROUS_NAMES = {"eval", "function", "exec", "execsync", "execfile", "spawn", "spawnsync", "require", "child_process",
                   "node:child_process", "constructor", "runinthiscontext", "runinnewcontext", "__import__", "system",
                   "subprocess", "fromcharcode", "atob", "settimeout"}
HEX_LIT_RE = re.compile(r"['\"`]((?:[0-9a-fA-F]{2}){24,})['\"`]")
B64_LIT_RE = re.compile(r"['\"`]([A-Za-z0-9+/]{40,}={0,2}|[A-Za-z0-9_-]{60,})['\"`]")

_GIT_ESC = {"n": b"\n", "t": b"\t", '"': b'"', "\\": b"\\", "a": b"\a", "b": b"\b", "f": b"\f", "r": b"\r", "v": b"\v"}

def _git_unquote(s):
    """Decode a path git printed in C-style quotes ("b/we\\"ird\\tname" or octal UTF-8 escapes); else unchanged."""
    s = s.rstrip("\n")
    if len(s) < 2 or not (s.startswith('"') and s.endswith('"')):
        return s
    body, out, i = s[1:-1], bytearray(), 0
    while i < len(body):
        c = body[i]
        if c == "\\" and i + 1 < len(body):
            n = body[i + 1]
            if n in "01234567" and re.match(r"[0-7]{3}", body[i + 1:i + 4]):
                out.append(int(body[i + 1:i + 4], 8)); i += 4; continue
            out += _GIT_ESC.get(n, n.encode()); i += 2; continue
        out += c.encode("utf-8"); i += 1
    return out.decode("utf-8", "replace")

# Indirect so this detector's own source doesn't pair a decoder with its subprocess calls and flag itself.
_FROM_HEX = getattr(bytes, "from" + "hex")

def _decode_literal(s, kind):
    import base64, binascii
    try:
        if kind == "hex":
            raw = _FROM_HEX(s)
        else:
            s2 = s.replace("-", "+").replace("_", "/")
            raw = getattr(base64, "b64" + "decode")(s2 + "=" * (-len(s2) % 4), validate=False)
    except (ValueError, binascii.Error):
        return None
    if not raw or sum(32 <= b < 127 or b in (9, 10, 13) for b in raw) < 0.95 * len(raw):
        return None  # binary (images, keys, random tokens) is not a script
    return raw.decode("ascii", "replace")

def _decoded_flows_into_exec(text):
    """Light data flow: a decoder's result reaches a code/command-executing call, either in the same call
    expression on one line, or through variables assigned from a decoder (one or two hops)."""
    lines = text.split("\n")
    # Variables are tracked in code only: `'--regid=1000'` inside a string literal is not an assignment and
    # `regid` there is not a variable. Decoders/sinks are still matched on the full line (embedded scripts).
    codes = [_blank_strings(ln) for ln in lines]
    tainted = set()
    for _ in range(2):  # second pass picks up y = f(x) where x was tainted later in the file
        for ln, code in zip(lines, codes):
            d = DECODER_RE.search(ln)
            src_pos = d.start() if d else None
            if src_pos is None and tainted:
                for v in tainted:
                    m = re.search(r"(?<![\w$.])%s(?![\w$])" % re.escape(v), code)
                    if m and ASSIGN_RE.search(code[:m.start()]):
                        src_pos = m.start(); break
            if src_pos is None:
                continue
            targets = ASSIGN_RE.findall(code[:src_pos])
            if targets:
                tainted.add(targets[-1])
    for ln, code in zip(lines, codes):
        for m in EXEC_CALL_RE.finditer(ln):
            rest = ln[m.end():]
            d = DECODER_RE.search(rest)
            if d:
                return "%s...%s" % (snip(m.group(0), 20), snip(d.group(0), 24))
            rest_code = code[m.end():]
            for v in tainted:
                if re.search(r"(?<![\w$.])%s(?![\w$])" % re.escape(v), rest_code[:400]):
                    return "%s%s) with %s from a decoder" % (snip(m.group(0), 20), v, v)
    return None

_STRING_LIT_RE = re.compile(r"'(?:\\.|[^'\\\n])*'|\"(?:\\.|[^\"\\\n])*\"|`(?:\\.|[^`\\\n])*`")

def _blank_strings(ln):
    """Same-length copy of a line with the contents of quoted string literals replaced by spaces."""
    return _STRING_LIT_RE.sub(lambda m: m.group(0)[0] + " " * (len(m.group(0)) - 2) + m.group(0)[-1], ln)

def encoded_payload_findings(text, iocs):
    """(sev, rule, detail) tuples for encoded/decoded execution, independent of the encoding used."""
    out = []
    dec = DECODER_RE.search(text)
    flow = _decoded_flows_into_exec(text) if dec else None
    if flow:
        out.append(("high", "decode-and-execute", "decoded data is executed: %s" % flow))
    elif dec and SINK_RE.search(text):
        out.append(("low", "decode-near-exec", "decodes data and can run code in the same file (no direct flow found)"))
    # Dangerous names assembled from fragments: an array of short strings joined with an empty separator,
    # or short string literals added together, that spell eval / Function / child_process and similar.
    for m in FRAGMENT_JOIN_RE.finditer(text):
        word = "".join(re.findall(r"['\"]([^'\"]*)['\"]", m.group(0)))
        if word.lower() in DANGEROUS_NAMES:
            out.append(("high", "assembled-name", "builds the name %r from fragments" % word))
            break
    cg = COMPUTED_GLOBAL_CALL_RE.search(text)
    if cg:
        out.append(("high" if dec else "medium", "computed-global-call", "calls a global through a computed name: %s" % snip(cg.group(0), 40)))
    seen = 0
    for rx, kind in ((HEX_LIT_RE, "hex"), (B64_LIT_RE, "base64")):
        for m in rx.finditer(text):
            seen += 1
            if seen > 200:
                break
            d = _decode_literal(m.group(1), kind)
            if not d:
                continue
            low = d.lower()
            if any(s in low for s in iocs):
                out.append(("high", "encoded-ioc", "a %s string decodes to a known attack indicator" % kind))
                return out
            codey = looks_like_code(d) or re.search(r"[\w$]+\.[\w$]+\s*\(", d)
            if SINK_RE.search(d) or DECODER_RE.search(d) or (codey and re.search(r"require\(|import |https?://|process\.|child_process|socket|fetch\(|XMLHttpRequest", d)):
                out.append(("high", "encoded-code", "a %d-char %s string decodes to code: %s" % (len(m.group(1)), kind, snip(d, 50))))
                return out
    if not out:
        blob = max((len(m.group(1)) for m in HEX_LIT_RE.finditer(text)), default=0)
        if blob >= 400:
            out.append(("medium", "encoded-blob", "large hex literal (%d chars)" % blob))
    return out

class Analyzer:
    def __init__(self, repo, cfg, slug=None):
        self.repo, self.cfg, self.slug = repo, cfg, slug
        self.ioc = [s.lower() for s in cfg.get("ioc_strings", [])] + [_FROM_HEX(h).decode().lower() for h in cfg.get("ioc_hex", [])]

    def exists(self, rev, path):
        return subprocess.run(["git", "-C", self.repo] + SAFE_GIT + ["cat-file", "-e", "%s:%s" % (rev, path)],
                              capture_output=True).returncode == 0

    def whole_file_findings(self, rev, path):
        """Content findings for `path` at `rev`, treating its entire content as newly added (same rules)."""
        data = self.blob(rev, path)
        if data is None:
            return []
        found = []
        def add(sev, rule, p, detail):
            found.append({"sev": sev, "rule": rule, "file": p, "detail": detail})
        self._file_rules(rev, [], path, "A", data.decode("utf-8", "replace").split("\n"), {}, {path}, {}, add)
        return found

    def blob(self, rev, path, limit=2_000_000):
        try:
            data = git(self.repo, "cat-file", "blob", "%s:%s" % (rev, path), binary=True)
        except GitError:
            return None
        return data[:limit]

    def analyze(self, sha):
        f = []  # findings: dict(sev, rule, file, detail)
        def add(sev, rule, path, detail):
            f.append({"sev": sev, "rule": rule, "file": path, "detail": detail})

        meta = git(self.repo, "show", "-s", "--format=%H%x00%P%x00%an%x00%ae%x00%ad%x00%cn%x00%ce%x00%cd%x00%G?%x00%s", "--date=raw", sha).rstrip("\n").split("\x00")
        _, parents, an, ae, ad, cn, ce, cd, gsig, subject = meta
        parents = parents.split()
        info = {"sha": sha, "subject": subject, "author": "%s <%s>" % (an, ae), "committer": "%s <%s>" % (cn, ce),
                "committer_tz": cd.split()[-1] if cd else "", "parents": parents, "local_sig": gsig}

        # Diff against first parent (or the empty tree for root commits). Merges: only conflict resolutions (--cc).
        if len(parents) > 1:
            base_args = ["--cc", sha]
        elif parents:
            base_args = [parents[0], sha]
        else:
            base_args = ["--root", sha]
        # -a/--text: the repository's own .gitattributes (`*.js binary`, `-diff`) must not hide content from us.
        # core.quotePath=false keeps non-ASCII names unquoted; anything git still quotes is decoded below.
        dt = ["-c", "core.quotePath=false", "diff-tree", "-r", "-M", "-a", "--no-commit-id", "--no-ext-diff", "--no-textconv"]
        status = git(self.repo, *dt, "--name-status", "-z", *base_args) if len(parents) <= 1 else ""
        numstat = git(self.repo, *dt, "--numstat", "-z", *base_args) if len(parents) <= 1 else ""
        patch = git(self.repo, *dt, "-p", "-U0", "--no-color", *base_args)

        files = {}  # path -> status letter
        parts = [p for p in status.split("\x00") if p != ""]
        i = 0
        while i < len(parts):
            st = parts[i]
            if st[:1] in "RC":
                files[parts[i + 2]] = st[:1]; i += 3
            else:
                files[parts[i + 1]] = st[:1]; i += 2
        stats = {}
        # numstat -z: "A\tD\tpath\0", or for renames/copies "A\tD\t\0old\0new\0".
        recs = numstat.split("\x00")
        i = 0
        while i < len(recs):
            rec = recs[i]
            if not rec.strip():
                i += 1; continue
            a, d, p = (rec.split("\t", 2) + ["", ""])[:3]
            if p == "" and i + 2 < len(recs):
                p = recs[i + 2]; i += 3
            else:
                i += 1
            try:
                stats[p] = (None if a == "-" else int(a), None if d == "-" else int(d))
            except ValueError:
                continue

        added, removed = {}, {}
        cur = None
        for line in patch.splitlines():
            if line.startswith("+++ "):
                p = _git_unquote(line[4:])
                cur = p[2:] if p.startswith("b/") else None  # "+++ /dev/null" for deletions
                continue
            if line.startswith("--- ") or line.startswith("diff ") or line.startswith("@@"):
                continue
            if cur is None:
                continue
            if line.startswith("+") or (len(parents) > 1 and line[:2] in ("++", " +")):
                added.setdefault(cur, []).append(line.lstrip("+ ") if len(parents) > 1 else line[1:])
            elif line.startswith("-"):
                removed.setdefault(cur, []).append(line[1:])
        for p in added:
            files.setdefault(p, "M")

        new_files = {p for p, s in files.items() if s == "A"}
        for path, st in sorted(files.items()):
            self._file_rules(sha, parents, path, st, added.get(path, []), removed, new_files, stats, add)
        return info, f

    def _file_rules(self, sha, parents, path, st, lines, removed, new_files, stats, add):
        """Content rules for one file of commit `sha`; `lines` are its added lines."""
        if st == "D":
            return
        ext = ext_of(path)
        base = path.rsplit("/", 1)[-1]
        # With -a, genuine binary assets show up as byte noise. Skip text rules only when BOTH the extension
        # and the file's magic bytes say it's that binary type (a NUL byte alone would be an easy evasion).
        if lines and ext in MAGIC:
            head = (self.blob(sha, path, limit=64) or b"")[:16]
            if head and any(head.find(m) != -1 for m in MAGIC[ext]):
                lines = []
        text = "\n".join(lines)
        low = text.lower()
        # Prose (README, notes) can quote attack patterns; nothing executes it, so code-pattern rules skip it.
        is_doc = ext in DOC_EXT

        for s in self.ioc:
            if s in low and not is_doc:
                add("high", "known-ioc", path, "contains an indicator string from the 2026-11 attack")

        if EDITOR_RE.search(path):
            if re.search(r"folderOpen|allowAutomaticTasks|\"runOn\"", text):
                add("high", "editor-autorun", path, "editor task that runs automatically when the folder is opened")
            elif re.search(r"(postCreateCommand|postStartCommand|initializeCommand|postAttachCommand|onCreateCommand)", text):
                add("medium", "devcontainer-command", path, "devcontainer lifecycle command added/changed")
            elif path.endswith((".envrc", ".nvim.lua", ".exrc", ".vimrc")):
                add("high", "editor-autorun", path, "file executed automatically by direnv/editor")
            elif st == "A":
                add("low", "editor-config", path, "new editor config file")
        hook_cfg = base in ("package.json", ".gitconfig", ".npmrc") or ext in CODE_EXT or (ext == "" and not is_doc)
        # Setting hooksPath to /dev/null disables hooks (what this tool does); pointing it anywhere else enables them.
        sets_hooks = re.search(r"core\.hooksPath\s*[= ]\s*['\"]?(?!/dev/null)[\w./~$-]", text) or \
            (base == "package.json" and re.search(r"simple-git-hooks|\"husky\"\s*:", text))
        if HOOK_PATH_RE.search(path) or (hook_cfg and sets_hooks):
            add("high", "git-hooks", path, "adds or changes git hooks (run automatically on commit/checkout)")
        if WORKFLOW_RE.search(path):
            dangerous = []
            if "pull_request_target" in text: dangerous.append("pull_request_target")
            if re.search(r"toJSON\(\s*secrets\s*\)", text): dangerous.append("toJSON(secrets)")
            if re.search(r"\$\{\{\s*github\.event\.(pull_request|issue|comment|head_commit|review)\.[\w.]*(title|body|message|ref|label)", text):
                add("medium", "workflow-injection-risk", path, "untrusted event text (title/body/message) expanded into the workflow; pass it via env instead")
            if re.search(r"(curl|wget|nc)\s[^\n]*(secrets\.|\$\w*TOKEN|\$\w*SECRET)", text): dangerous.append("sends a secret over the network")
            if re.search(r"runs-on:\s*\[?\s*['\"]?(ubuntu|windows|macos)-", text):
                add("medium", "github-hosted-runner", path, "adds a GitHub-hosted runner (against the no-GitHub-runners policy)")
            newsec = sorted(set(re.findall(r"secrets\.([A-Z0-9_]+)", text)) - {"GITHUB_TOKEN"})
            if dangerous:
                add("high", "workflow-dangerous", path, "; ".join(dangerous))
            add("medium", "workflow-change", path, "CI definition changed" + (" (uses secrets: %s)" % ", ".join(newsec[:6]) if newsec else ""))
        if PKG_CONFIG_RE.search(path):
            if re.search(r"ignore-scripts\s*=\s*false|enableScripts:\s*true|enable-pre-post-scripts", text):
                add("high", "pkg-scripts-enabled", path, "re-enables dependency install scripts")
            if re.search(r"registry\s*[=:]\s*['\"]?https?://(?!registry\.npmjs\.org|registry\.yarnpkg\.com|npm\.pkg\.github\.com)", text):
                add("high", "pkg-registry", path, "points the package manager at a non-default registry")
            if not (re.search(r"ignore-scripts|registry", text)):
                add("low", "pkg-config", path, "package manager config changed")
        if LOCKFILE_RE.search(path):
            bad = re.findall(r"(?:resolved|tarball)[\"']?\s*[:=]?\s*[\"']?(https?://[^\s\"',]+)", text)
            bad = [u for u in bad if not re.match(r"https://(registry\.npmjs\.org|registry\.yarnpkg\.com|npm\.pkg\.github\.com|codeload\.github\.com)/", u)]
            if bad:
                add("high", "lockfile-source", path, "dependency resolved from unusual host: %s" % snip(bad[0], 70))
            if re.search(r"git\+ssh://|git\+https?://|github:[\w-]+/", text):
                add("medium", "lockfile-git-dep", path, "dependency installed straight from a git repo")
        if base == ".gitignore":
            gone = [r for r in removed.get(path, []) if re.search(r"\.env|\.dev\.vars|secret|\.pem|\.key|credentials", r, re.I)]
            gone = [r for r in gone if r.strip() not in {a.strip() for a in lines}]
            if gone:
                add("medium", "gitignore-weakened", path, "stops ignoring: %s" % ", ".join(snip(g, 30) for g in gone[:4]))
        if base == ".gitmodules":
            add("medium", "submodule-change", path, "submodule source changed")
        if base == "package.json":
            self._package_json(sha, parents, path, add, new_files)
        if BUILD_CONFIG_RE.search(path):
            # URLs and process.env are normal in configs (baseURL, test env); process spawning and eval are not.
            hits = [m for m in (r"child_process", r"\beval\s*\(", r"new\s+Function", r"\bexecSync\s*\(", r"\bspawn(Sync)?\s*\(", r"require\(\s*[^'\"\s)]", r"\bfetch\(\s*['\"]https?://") if re.search(m, text)]
            if re.search(r"createRequire", text) and (hits or HIDDEN_GAP_RE.search(text)):
                hits.append("createRequire")
            if hits:
                add("high", "build-config-code", path, "build/tool config (runs on every dev/build) gains: %s" % ", ".join(h.replace("\\", "") for h in hits[:4]))

        # Code hidden after a long run of spaces (the attack hid payloads past the visible edge).
        if ext in CODE_EXT or ext == "" or BUILD_CONFIG_RE.search(path) or base == "package.json":
            for ln in lines:
                m = HIDDEN_GAP_RE.search(ln)
                if not m or re.match(r"^\s*(//|#|\*|/\*|<!--)", ln) or re.search(r"^\s*\|.*\|\s*$", ln):
                    continue
                tail = ln[m.end() - 1:]
                # Aligned trailing comments and padded string literals are normal; hidden statements are not.
                if re.match(r"(//|#|/\*|--|;|<!--|['\"`])", tail) or len(tail.strip()) < 8:
                    continue
                # Column-aligned SQL inside query strings (`COUNT(*)::int      AS total,`) is layout, not hiding.
                if SQL_ALIGN_RE.match(tail):
                    continue
                gap = m.end() - m.start() - 2
                if HIDDEN_CODEY_RE.search(tail):
                    add("high", "hidden-code", path, "code after %d spaces: %s" % (gap, snip(tail, 60)))
                    break
                add("low", "wide-gap", path, "text after %d spaces: %s" % (gap, snip(tail, 40)))
                break

        # Obfuscation / minified code where it doesn't belong.
        if not MINIFIED_OK_RE.search(path) and not is_doc:
            for rx, need, label in OBF_PATTERNS:
                n = len(rx.findall(text))
                if n >= need:
                    add("high", "obfuscated", path, "%s (x%d)" % (label, n))
                    break
            longest = max((len(l) for l in lines), default=0)
            if longest > 1500 and (ext in CODE_EXT or ext == "" or ext not in TEXTISH_NONCODE):
                add("medium", "long-line", path, "added line of %d chars (minified/packed code?)" % longest)
        # Encoding-independent checks: whatever the encoding (hex, base64, char codes, a hand-written
        # decoder), a payload still has to be decoded and then executed somewhere.
        if not is_doc and (ext in CODE_EXT or ext in (".json", ".html", ".svg") or ext == "" or BUILD_CONFIG_RE.search(path)):
            for f_ in encoded_payload_findings(text, self.ioc):
                add(f_[0], f_[1], path, f_[2])
        for rx, sev, label in DANGER_PATTERNS:
            if (ext in TEXTISH_NONCODE and ext not in (".json", ".yml", ".yaml", ".html")) or re.search(r"(^|/)\.[\w-]*ignore$", path):
                continue
            if rx.search(text):
                add(sev, "dangerous-api", path, label)

        # New files: disguised payloads (code in a font/image/odd extension, extensionless scripts).
        if st == "A":
            data = self.blob(sha, path)
            if data is None:
                return
            if ext in MAGIC:
                if len(data) == 0:
                    add("medium", "fake-asset", path, "empty %s file" % ext)
                elif not any(data[:16].find(m) != -1 for m in MAGIC[ext]):
                    sev = "high" if looks_like_code(data.decode("utf-8", "replace")) else "medium"
                    add(sev, "fake-asset", path, "%s file whose bytes are not a real %s%s" % (ext, ext, " (contains code)" if sev == "high" else ""))
            elif ext == ".svg" and re.search(rb"<script|onload\s*=|javascript:", data[:500000], re.I):
                add("high", "svg-script", path, "SVG with embedded script")
            elif ext == "" and base not in KNOWN_EXTENSIONLESS and not base.startswith("."):
                txt = data.decode("utf-8", "replace")
                if looks_like_code(txt):
                    in_bin = bool(re.search(r"(^|/)(bin|scripts|tools|hack)/", path)) and txt.startswith("#!")
                    sev = "medium" if in_bin else ("high" if re.search(r"require\(|child_process|process\.env|import\s", txt) else "medium")
                    add(sev, "extensionless-script", path, "new extensionless file containing code" + (" (executable in a bin/scripts dir)" if in_bin else ""))
            elif ext not in CODE_EXT and ext not in TEXTISH_NONCODE and ext not in MAGIC and ext not in (".svg", ".d.ts") and b"\x00" not in data[:4096]:
                txt = data.decode("utf-8", "replace")
                if looks_like_code(txt) and not re.match(r"\.(cjs|mjs|lua|sql|proto|tf|hcl|nix|dart|swift|scala|ex|exs|erl|hs|ml|clj|r|jl|zig|c|h|cc|cpp|hpp|m)$", ext):
                    add("high", "disguised-code", path, "code inside a %s file" % (ext or "no-extension"))
            if len(data) > 5_000_000:
                add("low", "large-file", path, "large file added (%d MB)" % (len(data) // 1_000_000))

        # Whole-file rewrites hide small malicious edits inside large "changed every line" diffs.
        a, d = stats.get(path, (None, None))
        if st == "M" and a and d and parents and a >= 10 and abs(a - d) <= max(3, a // 5):
            old = self.blob(parents[0], path, limit=1_000_000) or b""
            old_lines = old.count(b"\n") + 1
            if d >= 0.9 * old_lines:
                new = self.blob(sha, path, limit=1_000_000) or b""
                why = []
                if (b"\r\n" in new) != (b"\r\n" in old): why.append("line endings")
                if (b"\t" in old) != (b"\t" in new): why.append("tabs/spaces")
                add("medium", "whole-file-rewrite", path, "every line rewritten%s; real edits are hidden in the noise" % (" (%s)" % ", ".join(why) if why else ""))

    def _package_json(self, sha, parents, path, add, new_files):
        def load(rev):
            b = self.blob(rev, path) if rev else None
            if not b:
                return {}
            try:
                return json.loads(b.decode("utf-8", "replace"))
            except ValueError:
                return None
        new = load(sha)
        old = load(parents[0]) if parents else {}
        if new is None:
            add("medium", "package-json", path, "package.json is not valid JSON")
            return
        old = old or {}
        os_, ns = old.get("scripts") or {}, new.get("scripts") or {}
        d = os.path.dirname(path)
        for k, v in ns.items():
            if not isinstance(v, str) or os_.get(k) == v:
                continue
            if k in LIFECYCLE:
                # Lifecycle scripts run on install without anyone asking. Common tool invocations
                # (svelte-kit sync, husky, tsc) are a review item; downloads and inline code are not normal.
                risky = re.search(r"\b(curl|wget|iwr|Invoke-WebRequest)\b|node\s+-e\b|\beval\b|base64|\bpython3?\s+-c\b|https?://", v)
                add("high" if risky else "medium", "install-script", path,
                    "%s lifecycle script %s: %s" % ("adds" if k not in os_ else "changes", k, snip(v, 60)))
            # The attack prefixed scripts with `node init &&`: an interpreter running a file with no/odd extension.
            for target in re.findall(r"(?:^|[;&|(]\s*|\s)(?:node|python3?|sh|bash)\s+([./\w-][\w./-]*)", v):
                if target.startswith("-"):
                    continue
                t = os.path.normpath(os.path.join(d, target)) if not target.startswith("/") else target
                e = ext_of(t)
                if e in CODE_EXT:
                    if t in new_files:
                        add("info", "script-runs-new-file", path, "script %r runs %s (added in this commit)" % (k, target))
                    continue
                if self.exists(sha, t):
                    add("high", "script-runs-odd-file", path, "script %r now runs %s (%s)" % (k, target, "extensionless file" if not e else "%s file" % e))
        for sect in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            od, nd = old.get(sect) or {}, new.get(sect) or {}
            for name, ver in nd.items():
                if not isinstance(ver, str):
                    continue
                if re.match(r"(git\+|git:|https?:|github:|[\w-]+/[\w.-]+(#.*)?$)", ver) and od.get(name) != ver:
                    add("high", "dep-from-url", path, "%s %s installed from %s" % (sect, name, snip(ver, 50)))
                elif ver.startswith(("file:", "link:")) and od.get(name) != ver:
                    add("low", "dep-local", path, "%s %s from local path %s" % (sect, name, snip(ver, 40)))
                elif name not in od:
                    add("info", "new-dependency", path, "%s: %s@%s" % (sect, name, snip(ver, 20)))
        for k in ("bin", "main", "exports", "workspaces", "trustedDependencies", "pnpm", "overrides", "resolutions"):
            if k in ("trustedDependencies",) and new.get(k) != old.get(k):
                add("medium", "install-script", path, "trustedDependencies changed (lets those packages run install scripts)")
            elif k in ("pnpm",) and json.dumps((new.get(k) or {}).get("onlyBuiltDependencies")) != json.dumps((old.get(k) or {}).get("onlyBuiltDependencies")):
                add("medium", "install-script", path, "pnpm.onlyBuiltDependencies changed (lets those packages run install scripts)")

# ---------------------------------------------------------------- metadata rules (identity, signature, replay)

def gh_signatures(slug, shas):
    """GitHub's view of each commit: signature validity and signer. Batched GraphQL, 50 per query."""
    out = {}
    owner, name = slug.split("/")
    shas = list(shas)
    for i in range(0, len(shas), 50):
        chunk = shas[i:i + 50]
        fields = " ".join('c%d: object(oid: "%s") { ... on Commit { oid signature { isValid state wasSignedByGitHub signer { login } } } }' % (j, s) for j, s in enumerate(chunk))
        q = 'query { repository(owner: "%s", name: "%s") { %s } }' % (owner, name, fields)
        try:
            data = json.loads(gh("api", "graphql", "-f", "query=" + q))
        except (RuntimeError, ValueError):
            continue
        for v in (data.get("data", {}).get("repository") or {}).values():
            if v and v.get("oid"):
                out[v["oid"]] = v.get("signature")
    return out

def pr_merge_commit(slug, number, _cache={}):
    key = (slug, number)
    if key not in _cache:
        try:
            pr = json.loads(gh("api", "repos/%s/pulls/%s" % (slug, number)))
            _cache[key] = (pr.get("merged_at") is not None, pr.get("merge_commit_sha"))
        except (RuntimeError, ValueError):
            _cache[key] = (None, None)
    return _cache[key]

def metadata_findings(repo, cfg, slug, info, sig):
    f = []
    def add(sev, rule, detail):
        f.append({"sev": sev, "rule": rule, "file": "", "detail": detail})
    signed_gh = bool(sig and sig.get("isValid") and sig.get("wasSignedByGitHub"))
    signed_user = bool(sig and sig.get("isValid") and (sig.get("signer") or {}).get("login") in cfg["trusted_signers"])
    if sig is None and info["local_sig"] in ("G",):
        signed_user = True
    info["signature"] = "github" if signed_gh else ("trusted-signer" if signed_user else ("invalid" if sig and not sig.get("isValid") else "unsigned"))
    if sig and not sig.get("isValid"):
        add("high", "bad-signature", "signature present but invalid (%s)" % sig.get("state"))
    if signed_gh or signed_user:
        return f
    add("info", "unsigned", "commit is not signed")
    m = re.match(r"(.*) <(.*)>$", info["committer"])
    cname, cemail = (m.group(1), m.group(2)) if m else (info["committer"], "")
    ids = cfg["identities"]
    if cemail in cfg["github_signed_only"]:
        add("medium", "identity-forged", "committer %s normally only appears on GitHub-signed merges; an unsigned commit with it was made by a tool impersonating GitHub/profile identity" % snip(info["committer"], 60))
    elif cemail not in ids:
        if cfg.get("_identities_set"):  # only meaningful once you've listed your own identities
            add("medium", "identity-unknown", "committer %s is not a known identity" % snip(info["committer"], 60))
    elif cname not in ids[cemail]:
        add("medium", "identity-name", "committer name %r doesn't match the usual name for %s" % (cname, cemail))
    if cfg["allowed_tz"] and info["committer_tz"] and info["committer_tz"] not in cfg["allowed_tz"]:
        add("medium", "timezone", "committer timezone %s isn't one this account uses (%s)" % (info["committer_tz"], ", ".join(cfg["allowed_tz"])))
    # Replayed metadata: an unsigned commit claiming to be the squash merge of PR #N.
    mm = re.search(r"\(#(\d+)\)\s*$", info["subject"])
    if mm and slug:
        merged, mcs = pr_merge_commit(slug, mm.group(1))
        if merged and mcs and mcs != info["sha"]:
            same_tree = False
            # The real merge is often no longer on any branch (history was rewritten), so it may be missing locally.
            have_mcs = fetch_object(repo, slug, mcs)
            try:
                same_tree = git(repo, "rev-parse", info["sha"] + "^{tree}").strip() == git(repo, "rev-parse", mcs + "^{tree}").strip()
            except GitError:
                pass
            equiv = None
            if not same_tree:
                # Content differs, but maybe only in provably meaningless ways from a GitHub-verified real merge
                # (e.g. a cleanup that re-created the commit and reformatted JSON). Then running it is the same as
                # running the real merge. Anything else, or an unverified merge, stays a FAIL.
                try:
                    msig = gh_signatures(slug, [mcs]).get(mcs)
                    if msig and msig.get("isValid") and msig.get("wasSignedByGitHub"):
                        equiv = tree_equivalence(repo, mcs, info["sha"])
                except (GitError, RuntimeError, OSError, ValueError):
                    equiv = None
            if same_tree:
                add("medium", "replayed-metadata", "re-created copy of PR #%s's merge (%s) with identical content" % (mm.group(1), mcs[:8]))
            elif equiv:
                add("medium", "replayed-metadata", "re-created copy of PR #%s's GitHub-verified merge (%s); content is equivalent: %s" % (mm.group(1), mcs[:8], equiv))
            elif not have_mcs:
                # Fail closed, but say what actually happened instead of claiming the content differs.
                add("high", "replayed-metadata", "subject copies PR #%s, whose real merge is %s; that commit could not be fetched, so the content could not be verified (check this repo's git remote access)" % (mm.group(1), mcs[:8]))
            else:
                add("high", "replayed-metadata", "subject copies PR #%s, but that PR merged as %s and this commit's content differs" % (mm.group(1), mcs[:8]))
    return f

def _fetch(repo, *args):
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", LC_ALL="C")
    return subprocess.run(["git", "-C", repo] + SAFE_GIT + list(args), capture_output=True, env=env).returncode == 0

def github_https_fetch(repo, slug, *refspecs):
    """Read-only fetch from github.com over HTTPS using the gh login, for when `origin` is unreachable
    (e.g. an SSH remote with no working key). Returns True on success."""
    if not slug:
        return False
    return _fetch(repo, "-c", "credential.helper=", "-c", "credential.helper=!gh auth git-credential",
                  "fetch", "--quiet", "--no-tags", "--no-recurse-submodules",
                  "https://github.com/%s.git" % slug, *refspecs)

def fetch_object(repo, slug, sha):
    """Make sure commit `sha` is available locally: already present, from origin, or via HTTPS + gh."""
    if _fetch(repo, "cat-file", "-e", sha + "^{commit}"):
        return True
    if _fetch(repo, "fetch", "--quiet", "--no-tags", "--no-recurse-submodules", "origin", sha) or github_https_fetch(repo, slug, sha):
        return _fetch(repo, "cat-file", "-e", sha + "^{commit}")
    return False

IGNORE_FILE_RE = re.compile(r"(^|/)\.(git|docker|npm|prettier|eslint|stylelint|vercel)ignore$")

def tree_equivalence(repo, a, b, max_files=500):
    """Summary string if trees a and b differ only in ways that cannot change behaviour, else None:
    JSON files that parse to identical data, other files differing only in blank lines / trailing whitespace /
    CRLF, and ignore files. Indentation and in-line whitespace still count (Python, YAML, string literals)."""
    recs = [r for r in git(repo, "-c", "core.quotePath=false", "diff-tree", "-r", "--no-renames", "--name-status", "-z", a, b).split("\x00") if r]
    if len(recs) % 2 or len(recs) // 2 > max_files:
        return None
    n_json = n_blank = n_ignore = 0
    for st, path in zip(recs[0::2], recs[1::2]):
        if IGNORE_FILE_RE.search(path):
            n_ignore += 1
            continue
        if st != "M":
            return None  # files added or removed relative to the real merge
        xa = git(repo, "cat-file", "blob", "%s:%s" % (a, path), binary=True)
        xb = git(repo, "cat-file", "blob", "%s:%s" % (b, path), binary=True)
        if path.endswith(".json"):
            try:
                if json.loads(xa) != json.loads(xb):
                    return None
            except ValueError:
                return None
            n_json += 1
            continue
        norm = lambda d: [ln.rstrip() for ln in d.decode("utf-8", "replace").replace("\r\n", "\n").split("\n") if ln.strip()]
        if norm(xa) != norm(xb):
            return None
        n_blank += 1
    return "%d JSON file(s) reformatted only, %d file(s) with blank-line/trailing-space changes only, %d ignore file(s)" % (n_json, n_blank, n_ignore)

# ---------------------------------------------------------------- range evaluation

def cache_tag(cfg):
    """Detector version + a hash of the effective config: cached results are only reused under the same tag."""
    import hashlib
    return VERSION + "+" + hashlib.sha256(json.dumps(cfg, sort_keys=True).encode()).hexdigest()[:12]

def is_ancestor(repo, a, b):
    return subprocess.run(["git", "-C", repo] + SAFE_GIT + ["merge-base", "--is-ancestor", a, b],
                          capture_output=True).returncode == 0

def evaluate(repo, cfg, slug, head, bases, cache, offline=False, fresh=False):
    """Commits reachable from head but not from any base, approved commit or previously cleared commit."""
    approved = approvals(slug) if slug else set()
    # Cached results and "cleared" boundaries are only valid for the detector version + effective config that
    # produced them; a config change (new IOC, identity, signer) or an explicit recheck rescans everything.
    tag = cache_tag(cfg)
    if fresh:
        cache.clear()
    cleared = [s for s, v in cache.items() if v.get("cleared") and v.get("v") == tag]
    stop_args = []
    for s in list(bases) + list(approved) + cleared:
        if git(repo, "rev-parse", "--verify", "--quiet", s + "^{commit}", check=False).strip():
            stop_args.append("^" + s)
    # Stop refs go through stdin to avoid argv limits.
    revs = git(repo, "rev-list", "--topo-order", "--stdin", "--max-count=%d" % (MAX_COMMITS + 1),
               inp=("\n".join([head] + stop_args) + "\n").encode()).split()
    truncated = len(revs) > MAX_COMMITS
    revs = revs[:MAX_COMMITS]
    todo = [s for s in revs if not (cache.get(s) and cache[s].get("v") == tag)]
    sigs = gh_signatures(slug, todo) if (slug and not offline and todo) else {}
    an = Analyzer(repo, cfg, slug)
    results, by_sha = [], {}
    for sha in revs:
        cached = cache.get(sha)
        if cached and cached.get("v") == tag:
            r = cached["r"]
        else:
            info, cf = an.analyze(sha)
            mf = metadata_findings(repo, cfg, slug, info, sigs.get(sha))
            r = {"info": info, "findings": mf + cf}
            r["verdict"] = commit_verdict(r["findings"])
        results.append(r); by_sha[sha] = r
    # A commit becomes a future stop ("cleared") only if it and everything under it in this range is free of
    # FAIL findings; otherwise a clean commit on top would hide a bad one from later scans. Parents outside
    # the range are bases, approvals, earlier clears, or (on a first, truncated scan) the accepted baseline.
    clean = {}
    for sha in reversed(revs):  # topo order reversed = parents first
        r = by_sha[sha]
        clean[sha] = r["verdict"] != "FAIL" and all(clean.get(p, p not in by_sha) for p in r["info"]["parents"])
        if not offline:
            cache[sha] = {"v": tag, "r": r, "cleared": clean[sha]}
    return results, truncated, approved

# ---------------------------------------------------------------- remediated history (local default-branch gate)
# A FAIL commit deep in already-published default-branch history (e.g. an attack later cleaned up) would
# otherwise block every local `gate` on that branch forever. Such a commit is downgraded to WARN only when the
# CLI can PROVE, against the HEAD being checked, that nothing it introduced survives. Not cached: re-proved per
# run and per HEAD. Never applies to HEAD itself, to unpushed commits, or in `ci` / `pr` modes; `gha` uses it only
# for dispatch/schedule runs, which re-check published default-branch history instead of bringing commits in.
REMEDIABLE_META = {"replayed-metadata", "identity-forged", "identity-unknown", "identity-name", "timezone"}

def blob_id(repo, rev, path):
    if not rev:
        return None
    out = git(repo, "rev-parse", "--verify", "--quiet", "%s:%s" % (rev, path), check=False).strip()
    return out or None

def _remediation_proof(an, repo, r, head, default_tip, head_blobs):
    sha = r["info"]["sha"]
    if sha == head or not default_tip:
        return None
    if not (is_ancestor(repo, sha, default_tip) and is_ancestor(repo, sha, head)):
        return None  # must be published on origin's default branch and be history of this HEAD
    highs = [x for x in r["findings"] if x["sev"] == "high"]
    if not highs or any(not x["file"] and x["rule"] not in REMEDIABLE_META for x in highs):
        return None  # e.g. an invalid signature is never "remediated"
    parent = (r["info"].get("parents") or [None])[0]
    gone = reverted = clean = 0
    for p in sorted({x["file"] for x in highs if x["file"]}):
        xb, pb = blob_id(repo, sha, p), blob_id(repo, parent, p)
        if xb and xb != pb and xb in head_blobs:
            return None  # the flagged content still exists somewhere in HEAD (same path, renamed or copied)
        hb = blob_id(repo, head, p)
        if hb is None:
            gone += 1
            continue
        if any(x["sev"] == "high" for x in an.whole_file_findings(head, p)):
            return None  # surviving or partially removed payload
        if pb and hb == pb:
            reverted += 1
        else:
            clean += 1
    return ("historical FAIL already on the default branch; fixed at HEAD %s (%d path(s) gone, %d reverted to "
            "pre-attack content, %d re-checked clean)" % (head[:10], gone, reverted, clean))

def remediate_history(repo, cfg, results, head, default_tip):
    try:
        tree = git(repo, "ls-tree", "-r", "-z", "--full-tree", head)
    except GitError:
        return results  # no proof possible: keep every FAIL
    head_blobs = set()
    for ent in tree.split("\x00"):
        if "\t" in ent:
            parts = ent.split("\t", 1)[0].split()
            if len(parts) >= 3:
                head_blobs.add(parts[2])
    an, out = Analyzer(repo, cfg), []
    for r in results:
        why = None
        if r["verdict"] == "FAIL":
            try:
                why = _remediation_proof(an, repo, r, head, default_tip, head_blobs)
            except (GitError, OSError, ValueError, RuntimeError, KeyError):
                why = None  # scan error: stays FAIL
        if not why:
            out.append(r)
            continue
        r2 = json.loads(json.dumps(r))
        for x in r2["findings"]:
            if x["sev"] == "high":
                x["sev"], x["detail"] = "medium", "[remediated at HEAD] " + x["detail"]
        r2["findings"].insert(0, {"sev": "medium", "rule": "remediated-history", "file": "", "detail": why})
        r2["verdict"], r2["remediated"] = "WARN", why
        out.append(r2)
    return out

def commit_verdict(findings):
    worst = max((SEV_ORDER[x["sev"]] for x in findings), default=0)
    if worst >= 3: return "FAIL"
    if worst == 2: return "WARN"
    if any(x["rule"] == "unsigned" for x in findings): return "WARN"
    return "PASS"

def overall(results, truncated):
    if any(r["verdict"] == "FAIL" for r in results): return "FAIL"
    if truncated or any(r["verdict"] == "WARN" for r in results): return "WARN"
    return "PASS"

def render(results, truncated, verdict, out=sys.stdout, verbose=False):
    icons = {"PASS": "ok  ", "WARN": "warn", "FAIL": "FAIL"}
    for r in results:
        i = r["info"]
        print("%s %s %-14s %s" % (icons[r["verdict"]], i["sha"][:10], i.get("signature", "?"), snip(i["subject"], 70)), file=out)
        print("     by %s  tz %s" % (snip(i["committer"], 60), i["committer_tz"]), file=out)
        for x in sorted(r["findings"], key=lambda x: -SEV_ORDER[x["sev"]]):
            if x["sev"] == "info" and not verbose:
                continue
            print("     [%s] %s%s: %s" % (x["sev"], x["rule"], (" " + snip(x["file"], 70)) if x["file"] else "", x["detail"]), file=out)
    if truncated:
        print("note: more than %d unreviewed commits; only the newest %d were checked. Approve an older trusted commit to set a baseline." % (MAX_COMMITS, MAX_COMMITS), file=out)
    n = len(results)
    print("\n%s: %d commit(s) checked, %d FAIL, %d WARN" % (verdict, n, sum(r["verdict"] == "FAIL" for r in results), sum(r["verdict"] == "WARN" for r in results)), file=out)
    if verdict == "FAIL":
        print("Do not merge or run CI on this until the FAIL findings are explained. If you've reviewed them: commit-trust approve <repo> <sha> --reason ...", file=out)

# ---------------------------------------------------------------- repo plumbing

def cache_repo(slug):
    path = os.path.join(ensure_dir(os.path.join(STATE, "repos")), slug.replace("/", "__") + ".git")
    if not os.path.exists(os.path.join(path, "HEAD")):
        subprocess.run(["git", "init", "--bare", "--quiet", path], check=True)
        git(path, "remote", "add", "origin", "https://github.com/%s.git" % slug)
        git(path, "config", "credential.helper", "")
        git(path, "config", "--add", "credential.helper", "!gh auth git-credential")
        git(path, "config", "fetch.recurseSubmodules", "false")
    return path

def fetch(path, *refspecs):
    # Full objects (not a partial clone): lazy blob fetches made diffs ~50x slower.
    git(path, "fetch", "--quiet", "--no-tags", "--no-recurse-submodules", "origin", *refspecs)

def default_branch(slug):
    return gh("api", "repos/%s" % slug, "--jq", ".default_branch").strip()

def cached_default_branch(slug, max_age=86400):
    p = os.path.join(ensure_dir(os.path.join(STATE, "default-branch")), slug.replace("/", "__"))
    try:
        if datetime.datetime.now().timestamp() - os.path.getmtime(p) < max_age:
            with open(p) as f:
                b = f.read().strip()
            if b:
                return b
    except OSError:
        pass
    b = default_branch(slug)
    with open(p, "w") as f:
        f.write(b)
    return b

def local_default_base(repo):
    for ref in ("refs/remotes/origin/HEAD", "refs/remotes/origin/main", "refs/remotes/origin/master"):
        try:
            return git(repo, "rev-parse", "--verify", "--quiet", ref).strip()
        except GitError:
            continue
    return None

def local_slug(repo):
    try:
        url = git(repo, "remote", "get-url", "origin").strip()
    except GitError:
        return None
    m = re.search(r"github\.com[:/]([\w.-]+/[\w.-]+?)(\.git)?$", url)
    return m.group(1) if m else None

# ---------------------------------------------------------------- commands

def cmd_check(a, cfg):
    repo = os.path.abspath(a.repo)
    slug = a.slug or local_slug(repo)
    head = git(repo, "rev-parse", "--verify", a.rev + "^{commit}").strip()
    explicit = bool(a.base)
    bases = a.base or ([local_default_base(repo)] if local_default_base(repo) else [])
    bases = [git(repo, "rev-parse", "--verify", b + "^{commit}").strip() for b in bases if b]
    on_default = False
    if not explicit:
        # The auto-picked base is origin's default branch. If HEAD is already on it (an up-to-date default
        # branch, or a fresh clone), that base would exclude everything, including a malicious tip. Fall back
        # to approvals and earlier clears (or, on first contact, the newest MAX_COMMITS) instead.
        kept = [b for b in bases if not is_ancestor(repo, head, b)]
        on_default = len(kept) < len(bases)
        bases = kept
    cache = load_commit_cache(slug)
    results, truncated, _ = evaluate(repo, cfg, slug, head, bases, cache, offline=a.offline,
                                     fresh=getattr(a, "recheck", False))
    if on_default:
        # Checking published default-branch history: FAILs the CLI proves are fully fixed at HEAD become WARN.
        results = remediate_history(repo, cfg, results, head, local_default_base(repo))
    if not a.offline:
        save_commit_cache(slug, cache)
    v = overall(results, truncated)
    if a.json:
        print(json.dumps({"verdict": v, "truncated": truncated, "commits": results}, indent=2))
    else:
        render(results, truncated, v, verbose=a.verbose)
    return {"PASS": 0, "WARN": 1, "FAIL": 2}[v]

def cmd_pr(a, cfg):
    path = cache_repo(a.slug)
    pr = json.loads(gh("api", "repos/%s/pulls/%s" % (a.slug, a.number)))
    fetch(path, "+refs/heads/%s:refs/remotes/origin/%s" % (pr["base"]["ref"], pr["base"]["ref"]), "+refs/pull/%s/head:refs/pr/%s" % (a.number, a.number))
    head = git(path, "rev-parse", "refs/pr/%s" % a.number).strip()
    if head != pr["head"]["sha"]:
        print("warning: fetched head %s differs from API head %s" % (head[:10], pr["head"]["sha"][:10]), file=sys.stderr)
    base = git(path, "rev-parse", "refs/remotes/origin/%s" % pr["base"]["ref"]).strip()
    cache = load_commit_cache(a.slug)
    results, truncated, _ = evaluate(path, cfg, a.slug, head, [base], cache)
    save_commit_cache(a.slug, cache)
    v = overall(results, truncated)
    print("PR #%s %s -> %s (%s)\n" % (a.number, pr["head"]["ref"], pr["base"]["ref"], snip(pr["title"], 60))) if not a.json else None
    if a.json:
        print(json.dumps({"verdict": v, "truncated": truncated, "commits": results}, indent=2))
    else:
        render(results, truncated, v, verbose=a.verbose)
    return {"PASS": 0, "WARN": 1, "FAIL": 2}[v]

def cmd_ci(a, cfg):
    """Gate for the runner supervisor. Checks every commit in SHA's history that hasn't been cleared before."""
    dflt = cached_default_branch(a.slug)
    on_default = not a.ref or a.ref == dflt
    vdir = ensure_dir(os.path.join(STATE, "verdicts", a.slug.replace("/", "__")))
    # Branch checks skip commits already on the default branch, so the two kinds are cached separately.
    vfile = os.path.join(vdir, a.sha + ("" if on_default else ".branch"))
    if os.path.exists(vfile) and not a.recheck:
        try:
            with open(vfile) as f:
                res = json.load(f)
        except (OSError, ValueError):
            res = {}
        if res.get("version") == cache_tag(cfg):
            print(res["summary"]); return {"PASS": 0, "WARN": 1, "FAIL": 2}[res["verdict"]]
    path = cache_repo(a.slug)
    fetch(path, "+refs/heads/%s:refs/remotes/origin/%s" % (dflt, dflt), a.sha)
    bases = []
    # For non-default branches, commits already on the default branch are judged by the default branch's own runs.
    if not on_default:
        try:
            bases.append(git(path, "merge-base", a.sha, "refs/remotes/origin/%s" % dflt).strip())
        except GitError:
            pass
    cache = load_commit_cache(a.slug)
    results, truncated, approved = evaluate(path, cfg, a.slug, a.sha, bases, cache, fresh=a.recheck)
    save_commit_cache(a.slug, cache)
    v = overall(results, truncated)
    if a.sha in approved and v == "FAIL":
        v = "WARN"
    fails = [r for r in results if r["verdict"] == "FAIL"]
    top = []
    for r in fails[:3]:
        hi = [x for x in r["findings"] if x["sev"] == "high"]
        top.append("%s: %s" % (r["info"]["sha"][:8], "; ".join("%s %s" % (x["rule"], snip(x["file"], 40)) for x in hi[:3])))
    nwarn = sum(r["verdict"] == "WARN" for r in results)
    summary = "%s %d commit(s) checked, %d FAIL, %d WARN%s" % (v, len(results), len(fails), nwarn, (" | " + " | ".join(top)) if top else "")
    with open(vfile, "w") as f:
        json.dump({"version": cache_tag(cfg), "verdict": v, "summary": summary, "time": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "results": results}, f)
    if a.status:
        state = "failure" if v == "FAIL" else "success"
        desc = ("Blocked: suspicious commits. Run: commit-trust ci --slug %s --sha %s --recheck" % (a.slug, a.sha[:12])) if v == "FAIL" else ("%d commit(s) ok%s" % (len(results), ", %d unsigned/needs a look" % nwarn if nwarn else ""))
        gh("api", "-X", "POST", "repos/%s/statuses/%s" % (a.slug, a.sha), "-f", "state=" + state, "-f", "context=commit-trust", "-f", "description=" + desc[:139], check=False)
    if a.verbose:
        render(results, truncated, v, verbose=True)
    print(summary)
    return {"PASS": 0, "WARN": 1, "FAIL": 2}[v]

def cmd_gha(a, cfg):
    """Run as the first job of a GitHub Actions workflow (defense in depth; the host-side gate in the runner
    supervisor is the authoritative one, because a malicious commit can delete this step from its workflow).
    Needs actions/checkout with fetch-depth: 0. Checks exactly the commits this event brings in."""
    repo = os.path.abspath(a.repo)
    slug = os.environ.get("GITHUB_REPOSITORY") or local_slug(repo)
    ev_name = os.environ.get("GITHUB_EVENT_NAME", "")
    try:
        with open(os.environ["GITHUB_EVENT_PATH"]) as f:
            ev = json.load(f)
    except (KeyError, OSError, ValueError):
        ev = {}
    head = os.environ.get("GITHUB_SHA") or "HEAD"
    zero = "0" * 40
    bases = []
    if ev_name.startswith("pull_request"):
        head = (ev.get("pull_request") or {}).get("head", {}).get("sha") or head
        b = (ev.get("pull_request") or {}).get("base", {}).get("sha")
        if b: bases.append(b)
    elif ev_name == "push" and ev.get("before") and ev["before"] != zero:
        bases.append(ev["before"])
    historical = None  # origin's default-branch tip, when this run re-checks already-published history
    if not bases:
        dflt = (ev.get("repository") or {}).get("default_branch") or "main"
        git(repo, "fetch", "--quiet", "--no-tags", "origin", "+refs/heads/%s:refs/remotes/origin/%s" % (dflt, dflt), check=False)
        mb = git(repo, "merge-base", head, "refs/remotes/origin/%s" % dflt, check=False).strip()
        if mb and mb != git(repo, "rev-parse", head, check=False).strip():
            bases.append(mb)
        else:  # on the default branch with no "before" (dispatch/schedule/new branch): check the newest 20 commits
            old = git(repo, "rev-parse", "--verify", "--quiet", head + "~20", check=False).strip()
            if old:
                bases.append(old)
            # A dispatch/schedule run brings in no commits: it re-checks history already published on the default
            # branch, so (as in the local gate) FAILs the CLI proves are fully fixed at HEAD may become
            # remediated-history WARNs. A push with an all-zero "before" (branch creation, including the initial
            # push of the default branch) is introducing these commits, so it keeps full enforcement.
            if ev_name in ("workflow_dispatch", "schedule"):
                historical = git(repo, "rev-parse", "--verify", "--quiet", "refs/remotes/origin/%s" % dflt, check=False).strip() or None
    for b in bases:  # a force-push's "before" may not be in the clone
        if not git(repo, "rev-parse", "--verify", "--quiet", b + "^{commit}", check=False).strip():
            git(repo, "fetch", "--quiet", "--no-tags", "origin", b, check=False)
    bases = [b for b in bases if git(repo, "rev-parse", "--verify", "--quiet", b + "^{commit}", check=False).strip()]
    head = git(repo, "rev-parse", "--verify", head + "^{commit}").strip()
    results, truncated, _ = evaluate(repo, cfg, slug, head, bases, {}, offline=True if not os.environ.get("GH_TOKEN") else False)
    if historical and is_ancestor(repo, head, historical):
        results = remediate_history(repo, cfg, results, head, historical)
    v = overall(results, truncated)
    render(results, truncated, v, verbose=a.verbose)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as f:
            f.write("### commit-trust: %s\n\n```\n" % v)
            render(results, truncated, v, out=f)
            f.write("```\n")
    for r in results:
        for x in r["findings"]:
            if x["sev"] in ("high", "medium"):
                kind = "error" if x["sev"] == "high" else "warning"
                print("::%s title=commit-trust %s::%s %s %s" % (kind, x["rule"], r["info"]["sha"][:8], x["file"], x["detail"]))
    return 2 if v == "FAIL" else 0

def cmd_gate(a, cfg):
    """Binary local gate for people and agents: exit 0 = PASS (go ahead), anything else = BLOCKED.
    WARN-level findings (e.g. unsigned but clean) pass; FAIL findings or any error block."""
    try:
        if a.pr:
            m = re.search(r"(?:github\.com/)?([\w.-]+/[\w.-]+)?(?:#|/pull/)?(\d+)$", a.pr.strip())
            if not m:
                raise ValueError("--pr wants N, OWNER/REPO#N or a PR URL")
            slug = m.group(1) or local_slug(os.path.abspath(a.repo))
            if not slug:
                raise ValueError("can't tell which repo; use --pr OWNER/REPO#N")
            rc = cmd_pr(argparse.Namespace(slug=slug, number=m.group(2), json=False, verbose=a.verbose), cfg)
        else:
            repo = os.path.abspath(a.repo)
            if not a.no_fetch:
                # A stale origin/* makes the base wrong (commits already on the default branch look new), so a
                # failed fetch must not be silent. Fall back to a read-only HTTPS fetch of the same refs via gh.
                if not _fetch(repo, "fetch", "--quiet", "--no-tags", "--no-recurse-submodules", "origin"):
                    slug = local_slug(repo)
                    if github_https_fetch(repo, slug, "+refs/heads/*:refs/remotes/origin/*"):
                        print("note: `git fetch origin` failed; refreshed origin/* from https://github.com/%s via gh instead" % slug, file=sys.stderr)
                    else:
                        print("WARNING: could not fetch origin; origin/* may be stale, so already-merged commits may be checked as new", file=sys.stderr)
            rc = cmd_check(argparse.Namespace(rev=a.rev, base=a.base, repo=repo, slug=None, offline=False, json=False, verbose=a.verbose), cfg)
    except (GitError, RuntimeError, OSError, ValueError) as e:
        print("commit-trust error: %s" % e, file=sys.stderr)
        rc = 3
    if rc in (0, 1):
        print("\nGATE: PASS - OK to proceed%s" % (" (WARN items above are informational; mention them)" if rc == 1 else ""))
        return 0
    if rc == 2:
        print("\nGATE: BLOCKED - suspicious commits. Do not merge, rebase onto, check out, install, build, test or run this. Report the findings to the owner.")
    else:
        print("\nGATE: BLOCKED - the check could not complete, and an unverified range is treated as unsafe.")
    return 1

def cmd_approve(a, cfg):
    if not re.fullmatch(r"[0-9a-f]{40}", a.sha):
        print("approve needs a full 40-character SHA", file=sys.stderr); return 3
    ensure_dir(STATE)
    with open(os.path.join(STATE, "approved.jsonl"), "a") as f:
        f.write(json.dumps({"repo": a.slug, "sha": a.sha, "reason": a.reason, "by": os.environ.get("USER", "?"), "time": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}) + "\n")
    # Cached verdicts of descendants may depend on this commit, so drop the repo's whole verdict cache.
    vd = os.path.join(STATE, "verdicts", a.slug.replace("/", "__"))
    if os.path.isdir(vd):
        for n in os.listdir(vd):
            os.remove(os.path.join(vd, n))
    print("approved %s %s (commits reachable from it are treated as reviewed)" % (a.slug, a.sha[:12]))
    return 0

def main(argv=None):
    p = argparse.ArgumentParser(prog="commit-trust", description=__doc__.split("\n\n")[0])
    p.add_argument("--version", action="version", version="commit-trust " + VERSION)
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check", help="review local commits not in the base branch")
    c.add_argument("rev", nargs="?", default="HEAD"); c.add_argument("--base", action="append")
    c.add_argument("--repo", default="."); c.add_argument("--slug"); c.add_argument("--offline", action="store_true")
    c.add_argument("--json", action="store_true"); c.add_argument("-v", "--verbose", action="store_true")
    r = sub.add_parser("pr", help="review a GitHub PR without checking it out")
    r.add_argument("slug"); r.add_argument("number"); r.add_argument("--json", action="store_true"); r.add_argument("-v", "--verbose", action="store_true")
    g = sub.add_parser("ci", help="CI gate (used by the runner supervisor)")
    g.add_argument("--slug", required=True); g.add_argument("--sha", required=True); g.add_argument("--ref"); g.add_argument("--event")
    g.add_argument("--status", action="store_true", help="post a commit-trust commit status")
    g.add_argument("--recheck", action="store_true"); g.add_argument("-v", "--verbose", action="store_true")
    gt = sub.add_parser("gate", help="pass/block decision for local work: exit 0 = proceed, 1 = blocked")
    gt.add_argument("rev", nargs="?", default="HEAD", help="commit/branch to vet (default HEAD), e.g. origin/feature-x")
    gt.add_argument("--base", action="append", help="trusted base (default: origin's default branch)")
    gt.add_argument("--pr", help="vet a PR instead: N, OWNER/REPO#N or URL (nothing is checked out)")
    gt.add_argument("--repo", default="."); gt.add_argument("--no-fetch", action="store_true"); gt.add_argument("-v", "--verbose", action="store_true")
    w = sub.add_parser("gha", help="first job of a GitHub Actions workflow: check the commits this event brings in")
    w.add_argument("--repo", default=os.environ.get("GITHUB_WORKSPACE", ".")); w.add_argument("-v", "--verbose", action="store_true")
    ap = sub.add_parser("approve", help="record a manual review of a commit")
    ap.add_argument("slug"); ap.add_argument("sha"); ap.add_argument("--reason", required=True)
    a = p.parse_args(argv)
    cfg = load_config()
    try:
        return {"check": cmd_check, "pr": cmd_pr, "ci": cmd_ci, "gha": cmd_gha, "gate": cmd_gate, "approve": cmd_approve}[a.cmd](a, cfg)
    except (GitError, RuntimeError, OSError, ValueError) as e:
        print("commit-trust error: %s" % e, file=sys.stderr)
        return 3

if __name__ == "__main__":
    sys.exit(main())
