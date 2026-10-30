"""
Agentic Tool execution engine for OmniCLI.
Provides standard OpenAI function schemas and local execution for:
- bash command execution
- file reading and writing
- local Program Registry search (6,400+ tools)
- provider-to-provider LLM delegation (cross-API synergy)
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
import sqlite3
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


from omnicli.deterministic import (
    HTTPVerifier, CodeVerifier, PythonSecurityAnalyzer,
    CrossModelConsensusVerifier, ScopeGate,
)


def registry_db_path() -> Path:
    """Resolve the optional local registry database without a machine-specific path."""
    configured = os.environ.get("OMNICLI_REGISTRY_DB", "").strip()
    if configured:
        return Path(configured).expanduser()
    candidates = (
        Path.home() / "program_registry" / "core" / "program_registry.db",
        Path.home() / "program_registry.db",
    )
    return next((path for path in candidates if path.exists()), candidates[0])


_VCS_MARKERS = (".git", ".hg", ".svn")
_PROJECT_MARKERS = (
    "pyproject.toml", "setup.py", "setup.cfg", "package.json",
    "Cargo.toml", "go.mod", "pom.xml", "build.gradle", "build.gradle.kts",
    "settings.gradle", "settings.gradle.kts", "composer.json", "Gemfile",
    "mix.exs", "rebar.config", "dune-project", "CMakeLists.txt",
    "WORKSPACE", "WORKSPACE.bazel", "MODULE.bazel",
)
_WORKSPACE_IGNORED_DIRS = {
    ".git", ".hg", ".svn", "__pycache__", "venv", ".venv", "env",
    "node_modules", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    "dist", "build", ".egg-info", ".idea", ".vscode", ".tox", ".nox",
    ".cache", "target", "vendor",
}
_BINARY_SUFFIXES = {
    ".7z", ".a", ".avi", ".bin", ".bmp", ".bz2", ".class", ".db", ".dll",
    ".dylib", ".exe", ".gif", ".gz", ".ico", ".jar", ".jpeg", ".jpg",
    ".mkv", ".mov", ".mp3", ".mp4", ".o", ".pdf", ".png", ".pyc", ".pyo",
    ".rar", ".so", ".sqlite", ".sqlite3", ".tar", ".tgz", ".wasm", ".webp",
    ".xz", ".zip",
}
_TEXT_FILENAMES = {
    "BUILD", "CMakeLists.txt", "Dockerfile", "Gemfile", "Jenkinsfile",
    "Makefile", "MODULE.bazel", "Rakefile", "Vagrantfile", "WORKSPACE",
    "WORKSPACE.bazel",
}


def resolve_workspace_root(start: Optional[str | Path] = None) -> Path:
    """Resolve the active local workspace/project root.

    Resolution order: ``OMNICLI_WORKSPACE`` when it names a directory, the
    nearest ancestor containing a VCS marker, the nearest ancestor with a
    common project marker, then the starting directory itself. This mirrors
    a local coding CLI launched from a repository subdirectory. A marker in
    the user's home directory is not treated as a parent project root unless
    the process was started there.
    """
    configured = os.environ.get("OMNICLI_WORKSPACE", "").strip()
    if configured:
        configured_path = Path(configured).expanduser()
        try:
            configured_path = configured_path.resolve()
        except OSError:
            configured_path = configured_path.absolute()
        if configured_path.is_dir():
            return configured_path
        if configured_path.is_file():
            return configured_path.parent

    try:
        start_path = Path(start).expanduser() if start else Path.cwd()
    except Exception:
        start_path = Path.cwd()
    if not start_path.is_absolute():
        start_path = Path.cwd() / start_path
    try:
        start_path = start_path.resolve()
    except OSError:
        start_path = start_path.absolute()
    if start_path.is_file() or (not start_path.exists() and start_path.suffix):
        start_path = start_path.parent

    try:
        home = Path.home().resolve()
    except Exception:
        home = None

    ancestors = [start_path, *start_path.parents]
    for markers in (_VCS_MARKERS, _PROJECT_MARKERS):
        for candidate in ancestors:
            if home is not None and candidate == home and candidate != start_path:
                break
            if any((candidate / marker).exists() for marker in markers):
                return candidate
    return start_path


def resolve_workspace_path(
    path: str | Path,
    workspace_root: Optional[str | Path] = None,
) -> Path:
    """Resolve an operator/model path against CWD or the workspace root.

    Existing paths keep shell-like CWD semantics. If a relative path does not
    exist below CWD but exists below the discovered project root (the common
    case when OmniCLI is launched from a subdirectory and the model uses a
    repository-relative path), the repository path wins.
    """
    root = (
        Path(workspace_root).expanduser().resolve()
        if workspace_root else resolve_workspace_root()
    )
    raw = Path(path).expanduser() if str(path) else Path(".")
    if raw.is_absolute():
        return raw.resolve()

    cwd = Path.cwd().resolve()
    if str(raw) in ("", "."):
        return cwd
    cwd_candidate = (cwd / raw).resolve()
    if cwd_candidate.exists():
        return cwd_candidate
    root_candidate = (root / raw).resolve()
    if root_candidate.exists():
        return root_candidate
    if raw.parts:
        first = raw.parts[0]
        if (root / first).is_dir() and not (cwd / first).exists():
            return root_candidate
    return root_candidate


def _coerce_workspace_root(workspace_root: Optional[str | Path] = None) -> Path:
    """Use an explicit workspace root as-is; otherwise discover it."""
    if workspace_root:
        return Path(workspace_root).expanduser().resolve()
    return resolve_workspace_root()


def tool_verify_http(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    body: Optional[str] = None,
    expected: str = "",
    allow_local: bool = False,
    allowed_hosts: Optional[List[str]] = None,
    allow_mutating_http: bool = False,
) -> str:
    """Execute deterministic HTTP verification and return verdict.

    The agent must receive an explicit host allowlist before it can probe any
    target. Private/local hosts additionally require allow_local. State-changing
    methods additionally require allow_mutating_http.
    """
    scoped_hosts = [
        host.strip() for host in (allowed_hosts or [])
        if isinstance(host, str) and host.strip()
    ]
    if not scoped_hosts:
        return json.dumps({
            "verdict": "REJECTED",
            "reason": "HTTP verification requires at least one operator-configured allowed host.",
            "url": url,
            "observed": None,
        }, indent=2)

    normalized_method = str(method or "GET").strip().upper()
    if not normalized_method:
        normalized_method = "GET"
    if normalized_method not in {"GET", "HEAD", "OPTIONS"} and not allow_mutating_http:
        return json.dumps({
            "verdict": "REJECTED",
            "reason": (
                f"HTTP method '{normalized_method}' may change state; "
                "operator consent via --allow-mutating-http is required."
            ),
            "url": url,
            "observed": None,
        }, indent=2)

    gate = ScopeGate(
        allowed_hosts=scoped_hosts,
        allow_localhost=allow_local,
        allow_private=allow_local,
    )
    res = HTTPVerifier.verify(
        url=url,
        method=normalized_method,
        headers=headers,
        body=body,
        expected_str=expected,
        scope_gate=gate,
    )
    res["verification_type"] = "http_response_predicates"
    res["security_vulnerability_confirmed"] = False
    res["interpretation"] = (
        "This result confirms or rejects only the specified HTTP response predicates; "
        "it does not independently establish that the behavior is a vulnerability."
    )
    return json.dumps(res, indent=2)


def _coerce_patterns(val: Any) -> Optional[List[str]]:
    """Normalise a must_(not_)contain argument into a list of strings.

    Models frequently pass a JSON-encoded list string (e.g. '["a","b"]') or a
    single bare pattern instead of an array; both are coerced to a real list so
    the verifier does not iterate a string character-by-character.
    """
    if val is None:
        return None
    if isinstance(val, (list, tuple)):
        return [str(x) for x in val]
    if isinstance(val, str):
        s = val.strip()
        if s.startswith("[") and s.endswith("]"):
            try:
                parsed = json.loads(s)
                if isinstance(parsed, list):
                    return [str(x) for x in parsed]
            except json.JSONDecodeError:
                pass
        return [val]
    return [str(val)]


def tool_verify_code(
    path: str,
    must_contain: Optional[List[str]] = None,
    must_not_contain: Optional[List[str]] = None,
    target_function: Optional[str] = None,
    check_type: Optional[str] = None,
    workspace_root: Optional[str | Path] = None,
) -> str:
    """Execute deterministic code pattern verification and return verdict."""
    root = _coerce_workspace_root(workspace_root)
    resolved = resolve_workspace_path(path, workspace_root=root)
    res = CodeVerifier.verify_file(
        file_path=str(resolved),
        must_contain=_coerce_patterns(must_contain),
        must_not_contain=_coerce_patterns(must_not_contain),
        target_function=target_function,
        check_type=check_type,
        allowed_dirs=[root],
    )
    res["verification_type"] = "literal_source_pattern"
    res["security_vulnerability_confirmed"] = False
    res["interpretation"] = (
        "This result confirms or rejects only literal source-pattern constraints; "
        "a match does not prove exploitability and a non-match does not prove safety."
    )
    return json.dumps(res, indent=2)


def tool_analyze_python_security(
    path: str,
    target_function: Optional[str] = None,
    workspace_root: Optional[str | Path] = None,
) -> str:
    """Analyze Python source for direct input-to-SQL interpolation candidates."""
    root = _coerce_workspace_root(workspace_root)
    resolved = resolve_workspace_path(path, workspace_root=root)
    res = PythonSecurityAnalyzer.analyze_file(
        file_path=str(resolved),
        allowed_dirs=[root],
        target_function=target_function,
    )
    res["verification_type"] = "python_ast_security_pattern"
    res["security_vulnerability_confirmed"] = False
    res["interpretation"] = (
        "CANDIDATES_FOUND identifies source-level input-to-SQL interpolation "
        "candidates only; it does not confirm reachability or exploitability. "
        "NO_PATTERN_FOUND is not proof that the code is safe."
    )
    return json.dumps(res, indent=2)


def tool_verify_consensus(
    claim: str,
    evidence: str,
    models: Optional[List[str]] = None,
    client_ref: Any = None,
) -> str:
    """Run cross-model / cross-provider verification consensus."""
    if client_ref is None:
        return "Error: Client reference required for consensus verification."
    model_specs = []
    if models:
        for m in models:
            if ":" in m:
                p, mod = m.split(":", 1)
                model_specs.append((p.strip(), mod.strip()))
            else:
                model_specs.append((m.strip(), None))
    verifier = CrossModelConsensusVerifier(client_ref)
    res = verifier.verify_finding(claim, evidence, models=model_specs or None)
    return json.dumps(res, indent=2)


# Destructive / exfil-to-shell command patterns refused even when the shell is
# enabled. This is a backstop against a prompt-injected model, not a full sandbox.
_BASH_DENY_PATTERNS = [
    r"\brm\s+-[a-z]*r[a-z]*f[a-z]*\s+(/|~|\$HOME|\*)",  # rm -rf / ~ * $HOME
    r"\brm\s+-[a-z]*f[a-z]*r[a-z]*\s+(/|~|\$HOME|\*)",  # rm -fr ...
    r"\bmkfs\b",                                        # format a filesystem
    r"\bdd\b[^\n]*\bof=/dev/",                          # overwrite a block device
    r">\s*/dev/(sd|nvme|hd|vd)",                        # clobber a disk
    r":\s*\(\s*\)\s*\{.*\}\s*;\s*:",                    # fork bomb :(){ :|:& };:
    r"\b(shutdown|reboot|halt|poweroff|init\s+0)\b",   # host power control
    r"\bchmod\s+-R\s+0*777\s+/",                        # chmod -R 777 /
    r"\bchown\s+-R\b[^\n]*\s+/\s*$",                    # chown -R ... /
    r"(curl|wget)\b[^|;&\n]*\|\s*(sudo\s+)?(ba)?sh",   # pipe a download into a shell
    r">\s*/etc/",                                       # overwrite system config
    # The agent's own credential stores: a prompt-injected model must never
    # read back the API keys it runs on (cat via any home spelling).
    r"\.config/omnicli\b",
    r"\.config/trio/keys\.env\b",
    r"oauth-keys\.env\b",
]


def _bash_denied(command: str) -> Optional[str]:
    """Return the matched deny-pattern if command is destructive, else None."""
    for pat in _BASH_DENY_PATTERNS:
        if re.search(pat, command, re.IGNORECASE):
            return pat
    return None


def tool_bash(
    command: str,
    timeout: int = 30,
    allow_shell: bool = False,
    workspace_root: Optional[str | Path] = None,
) -> str:
    """Execute a bash command in the local environment.

    Shell execution is OFF by default: the agent must be started with
    --allow-shell (allow_shell=True) to enable it. Even when enabled, commands
    matching _BASH_DENY_PATTERNS are refused as a backstop against a
    prompt-injected model steering the agent into a destructive command.
    """
    if not allow_shell:
        return (
            "Error: shell execution is disabled. Re-run the agent with "
            "--allow-shell to enable the bash tool."
        )
    denied = _bash_denied(command)
    if denied:
        return (
            f"Error: command refused by safety policy (matched deny pattern: {denied}). "
            "Destructive or download-to-shell commands are blocked."
        )
    try:
        try:
            timeout = int(timeout) if timeout not in (None, "None", "") else 30
        except (ValueError, TypeError):
            timeout = 30
        res = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
            # The shell starts in the project workspace, not at an
            # arbitrary process directory or the home directory.
            cwd=str(_coerce_workspace_root(workspace_root)),
        )
        out = res.stdout
        err = res.stderr
        code = res.returncode
        result = []
        if out:
            result.append(f"STDOUT:\n{out}")
        if err:
            result.append(f"STDERR:\n{err}")
        result.append(f"Exit Code: {code}")
        return "\n".join(result)
    except subprocess.TimeoutExpired:
        return f"Error: Command timed out after {timeout} seconds."
    except Exception as e:
        return f"Error executing bash: {e}"


def check_workspace_jail(
    path: str | Path,
    workspace_root: Optional[str | Path] = None,
) -> Path:
    """Resolve a path and require it to remain inside the active workspace."""
    root = _coerce_workspace_root(workspace_root)
    p = resolve_workspace_path(path, workspace_root=root)
    try:
        p.relative_to(root)
    except ValueError:
        raise PermissionError(
            f"Security Policy: path '{path}' resolves outside the allowed workspace '{root}'"
        ) from None
    return p


def format_tool_error(code: str, message: str, remedy: str = "") -> str:
    """Standardized tool error envelope for immediate agent comprehension."""
    err = {
        "status": "error",
        "code": code,
        "message": message,
    }
    if remedy:
        err["remedy"] = remedy
    return f"Error: {message}\n" + json.dumps(err, indent=2)


def tool_list_directory(
    path: str = ".",
    max_depth: int = 2,
    workspace_root: Optional[str | Path] = None,
) -> str:
    """List directory contents (files and folders) within the project workspace."""
    try:
        p = check_workspace_jail(path, workspace_root=workspace_root)
    except PermissionError as pe:
        return format_tool_error("E_PERMISSION", str(pe), "Choose a path inside the project workspace.")

    if not p.exists():
        return format_tool_error("E_NOT_FOUND", f"Directory '{path}' does not exist.", "Check directory path spelling.")
    if not p.is_dir():
        return format_tool_error("E_NOT_DIR", f"'{path}' is a file, not a directory.", "Use read_file to inspect files.")

    try:
        try:
            max_depth = int(max_depth) if max_depth not in (None, "None", "") else 2
        except (ValueError, TypeError):
            max_depth = 2

        entries = []
        root_path = p.resolve()
        ignored_names = {
            ".git", "__pycache__", "venv", ".venv", "env", "node_modules",
            ".pytest_cache", ".mypy_cache", ".ruff_cache", "dist", "build",
            ".egg-info", ".idea", ".vscode"
        }

        for current_root, dirs, files in os.walk(root_path):
            curr = Path(current_root)
            try:
                rel = curr.relative_to(root_path)
            except ValueError:
                continue
            depth = len(rel.parts)
            # Prune ignored directories in place
            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ignored_names]
            if depth >= max_depth:
                dirs.clear()

            prefix = "" if str(rel) == "." else f"{rel}/"
            for d in sorted(dirs):
                entries.append(f"📁 {prefix}{d}/")
            for f in sorted(files):
                if f.startswith("."):
                    continue
                fpath = curr / f
                try:
                    st = fpath.stat()
                    size_b = st.st_size
                    size_str = f"{size_b:,} B" if size_b < 1024 else f"{size_b / 1024:.1f} KB"
                    entries.append(f"📄 {prefix}{f} ({size_str})")
                except OSError:
                    entries.append(f"📄 {prefix}{f}")

                if len(entries) >= 250:
                    entries.append("... [truncated, directory contains > 250 items]")
                    break
            if len(entries) >= 250:
                break

        header = f"--- Directory listing: {p} ({len(entries)} items) ---\n"
        return header + "\n".join(entries)
    except Exception as e:
        return format_tool_error("E_IO", f"Error listing directory: {e}")


_SENSITIVE_FILE_RE = re.compile(
    r"(?:^|/)(?:"
    r"\.env(?:\..*)?|"
    r"\.netrc|\.npmrc|\.pypirc|"
    r"id_(?:rsa|dsa|ecdsa|ed25519)(?:\.pub)?|"
    r"credentials?(?:\..*)?|secrets?(?:\..*)?|"
    r"tokens?(?:\..*)?|passwords?(?:\..*)?"
    r")$|\.(?:pem|key|p12|pfx|jks|keystore|kdbx)$",
    re.IGNORECASE,
)


def _is_sensitive_path(relative_path: str) -> bool:
    """True for obvious credential/private-key filenames.

    Directory scans are broad and opt-in; silently shipping an `.env` or a
    private key to a model provider is not an acceptable default. An explicit
    single-file read can still include it when the operator names it.
    """
    return bool(_SENSITIVE_FILE_RE.search(relative_path.replace("\\", "/")))


def _fallback_gitignore_match(relative_path: str, patterns: List[str]) -> bool:
    """Best-effort root .gitignore matching for non-git executable fallback."""
    ignored = False
    rel = relative_path.replace("\\", "/")
    parts = rel.split("/")
    for raw in patterns:
        pattern = raw.strip()
        if not pattern or pattern.startswith("#"):
            continue
        negated = pattern.startswith("!")
        if negated:
            pattern = pattern[1:]
        directory_only = pattern.endswith("/")
        pattern = pattern.strip("/")
        if not pattern:
            continue
        if "/" in pattern:
            matched = fnmatch.fnmatch(rel, pattern) or rel.startswith(pattern + "/")
        else:
            matched = any(fnmatch.fnmatch(part, pattern) for part in parts)
        if matched and (not directory_only or len(parts) > 1):
            ignored = not negated
    return ignored


def _iter_workspace_files(
    root: str | Path,
    *,
    include_sensitive: bool = False,
) -> List[Path]:
    """List workspace files in deterministic order, honoring Git ignores."""
    base = Path(root).expanduser().resolve()
    if not base.is_dir():
        return []

    rel_paths: Optional[List[str]] = None
    if (base / ".git").exists():
        try:
            result = subprocess.run(
                ["git", "-C", str(base), "ls-files", "--cached",
                 "--others", "--exclude-standard", "-z"],
                capture_output=True,
                timeout=5,
                check=False,
            )
            if result.returncode == 0:
                rel_paths = [
                    item for item in os.fsdecode(result.stdout).split("\0") if item
                ]
        except Exception:
            rel_paths = None

    files: List[Path] = []
    if rel_paths is not None:
        for rel in rel_paths:
            rel_posix = rel.replace("\\", "/")
            if not include_sensitive and _is_sensitive_path(rel_posix):
                continue
            candidate = (base / rel).resolve()
            try:
                candidate.relative_to(base)
            except ValueError:
                continue
            if candidate.is_file():
                files.append(candidate)
        return files

    gitignore = base / ".gitignore"
    try:
        ignore_patterns = gitignore.read_text(
            encoding="utf-8", errors="replace"
        ).splitlines() if gitignore.is_file() else []
    except OSError:
        ignore_patterns = []
    for current_root, dirs, names in os.walk(base):
        current = Path(current_root)
        kept_dirs = []
        for dirname in sorted(dirs):
            if dirname in _WORKSPACE_IGNORED_DIRS:
                continue
            if dirname.startswith(".") and dirname != ".github":
                continue
            rel_dir = str((current / dirname).relative_to(base)).replace("\\", "/")
            if _fallback_gitignore_match(rel_dir + "/", ignore_patterns):
                continue
            kept_dirs.append(dirname)
        dirs[:] = kept_dirs
        for name in sorted(names):
            candidate = current / name
            rel = str(candidate.relative_to(base)).replace("\\", "/")
            if _fallback_gitignore_match(rel, ignore_patterns):
                continue
            if not include_sensitive and _is_sensitive_path(rel):
                continue
            if candidate.is_symlink():
                try:
                    if not candidate.resolve().is_relative_to(base):
                        continue
                except OSError:
                    continue
            if candidate.is_file():
                files.append(candidate)
    return files


def _read_text_file(path: Path, max_bytes: int = 2_000_000) -> Optional[str]:
    """Read a likely-text file with a bounded size; None for binary/large."""
    if path.suffix.lower() in _BINARY_SUFFIXES:
        return None
    try:
        if path.stat().st_size > max_bytes:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if b"\0" in data[:8192]:
        return None
    return data.decode("utf-8", errors="replace")


def _matches_glob(relative_path: str, pattern: str) -> bool:
    rel = relative_path.replace("\\", "/")
    pat = pattern.replace("\\", "/")
    try:
        if Path(rel).match(pat):
            return True
    except ValueError:
        pass
    return fnmatch.fnmatch(rel, pat) or (
        "/" not in pat and fnmatch.fnmatch(Path(rel).name, pat)
    )


def scan_directory_sources(
    directory: str | Path = ".",
    max_chars: int = 200_000,
    allowed_extensions: Optional[Set[str]] = None,
    include_sensitive: bool = False,
) -> Dict[str, str]:
    """Scan directory recursively and load readable source files up to max_chars.

    Symlinked files that resolve outside the scanned root are skipped, and
    credential-like filenames are excluded unless ``include_sensitive`` is
    explicitly set.
    """
    p = Path(directory).expanduser().resolve()
    if not p.is_dir():
        return {}

    extensions = allowed_extensions or {
        ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rs", ".php",
        ".rb", ".c", ".cpp", ".h", ".hpp", ".java", ".sh", ".bash",
        ".sql", ".json", ".yaml", ".yml", ".toml", ".html", ".css", ".md",
    }
    ignored_names = {
        ".git", "__pycache__", "venv", ".venv", "env", "node_modules",
        ".pytest_cache", ".mypy_cache", ".ruff_cache", "dist", "build",
        ".egg-info", ".idea", ".vscode"
    }

    results: Dict[str, str] = {}
    total_chars = 0

    for current_root, dirs, files in os.walk(p):
        curr = Path(current_root)
        dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ignored_names]

        for f in sorted(files):
            fpath = curr / f
            if fpath.suffix.lower() not in extensions:
                continue
            try:
                rel_path = str(fpath.relative_to(p)).replace("\\", "/")
            except ValueError:
                rel_path = str(fpath).replace("\\", "/")
            if not include_sensitive and _is_sensitive_path(rel_path):
                continue
            if fpath.is_symlink():
                try:
                    if not fpath.resolve().is_relative_to(p):
                        continue
                except OSError:
                    continue

            try:
                # Skip giant binary or data files (> 200KB)
                if fpath.stat().st_size > 200_000:
                    continue
                content = fpath.read_text(encoding="utf-8", errors="replace")
                if not content.strip():
                    continue
                if total_chars + len(content) > max_chars:
                    remaining = max_chars - total_chars
                    suffix = "\n... [truncated to fit 200k char budget]"
                    if remaining > len(suffix) + 50:
                        results[rel_path] = content[: remaining - len(suffix)] + suffix
                    total_chars = max_chars
                    break
                results[rel_path] = content
                total_chars += len(content)
            except Exception:
                continue

        if total_chars >= max_chars:
            break

    return results


def tool_read_file(
    path: str,
    max_lines: int = 300,
    start_line: int = 1,
    end_line: Optional[int] = None,
    workspace_root: Optional[str | Path] = None,
) -> str:
    """Read a numbered line range from a local file inside the workspace."""
    try:
        p = check_workspace_jail(path, workspace_root=workspace_root)
    except PermissionError as pe:
        return format_tool_error("E_PERMISSION", str(pe), "Choose a path inside the project workspace.")

    if not p.exists():
        return format_tool_error("E_NOT_FOUND", f"File '{path}' does not exist.", "Check file path spelling and location.")
    if p.is_dir():
        return tool_list_directory(str(p), workspace_root=workspace_root)
    if not p.is_file():
        return format_tool_error("E_NOT_FILE", f"'{path}' is not a regular file.", "Specify a file path or directory.")

    def _coerce(value: Any, default: int) -> int:
        try:
            return int(value) if value not in (None, "None", "") else default
        except (ValueError, TypeError):
            return default

    start = max(1, _coerce(start_line, 1))
    line_budget = max(1, min(_coerce(max_lines, 300), 2000))
    end = _coerce(end_line, 0) if end_line is not None else None
    if end is not None:
        if end < start:
            return format_tool_error(
                "E_INVALID", "end_line must be greater than or equal to start_line."
            )
        line_budget = min(line_budget, end - start + 1)

    try:
        selected: List[Tuple[int, str]] = []
        total_lines = 0
        with open(p, "r", encoding="utf-8", errors="replace") as f:
            for number, raw_line in enumerate(f, start=1):
                total_lines = number
                if number < start or len(selected) >= line_budget:
                    continue
                if end is not None and number > end:
                    continue
                selected.append((number, raw_line.rstrip("\r\n")))
        total_chars = sum(len(line) for _number, line in selected)
        if selected:
            shown_start, shown_end = selected[0][0], selected[-1][0]
            header = (
                f"--- {p} (lines {shown_start}-{shown_end} of "
                f"{total_lines}, {total_chars} chars) ---\n"
            )
            body = "\n".join(
                f"{number:05d} | {line}" for number, line in selected
            )
            return header + body + ("\n" if body else "")
        header = f"--- {p} (lines {start}-{total_lines} of {total_lines}) ---\n"
        return header + "(start_line is beyond the end of the file)\n"
    except Exception as e:
        return format_tool_error("E_IO", f"Error reading file: {e}")


def net_open_brackets(text: str) -> int:
    """Net count of unclosed (, [, and {."""
    open_count = 0
    for ch in text:
        if ch in "([{":
            open_count += 1
        elif ch in ")]}":
            open_count -= 1
    return open_count


def detect_truncated_rewrite(old_content: str, new_content: str) -> Optional[Dict[str, Any]]:
    """Truncated write guard: refuses replacing a file with a much shorter copy
    that stops mid-expression with unclosed syntax."""
    old_lines = len(old_content.splitlines())
    if old_lines < 30:
        return None
    if len(new_content) >= len(old_content) * 0.6:
        return None
    if net_open_brackets(old_content) != 0:
        return None
    open_brackets = net_open_brackets(new_content)
    if open_brackets <= 0:
        return None
    trimmed = new_content.rstrip()
    last_line = trimmed.splitlines()[-1].strip() if trimmed.splitlines() else ""
    return {
        "old_lines": old_lines,
        "new_lines": len(new_content.splitlines()),
        "open_brackets": open_brackets,
        "last_line": last_line[-100:] if len(last_line) > 100 else last_line,
    }


def tool_write_file(
    path: str,
    content: str,
    workspace_root: Optional[str | Path] = None,
) -> str:
    """Write or overwrite a local file with truncation and jail protection."""
    try:
        p = check_workspace_jail(path, workspace_root=workspace_root)
    except PermissionError as pe:
        return format_tool_error("E_PERMISSION", str(pe), "Choose a path inside the project workspace.")

    if p.exists() and p.is_file():
        try:
            old_c = p.read_text(encoding="utf-8", errors="replace")
            trunc = detect_truncated_rewrite(old_c, content)
            if trunc:
                return (
                    f"Error: Refused to write '{p}': The new content ({trunc['new_lines']} lines) "
                    f"is far shorter than current file ({trunc['old_lines']} lines) and ends with "
                    f"{trunc['open_brackets']} unclosed bracket(s) (last line: '{trunc['last_line']}'). "
                    f"Truncated-write-guard prevented file corruption. Re-issue full content."
                )
        except Exception:
            pass
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        return f"Successfully wrote {len(content)} characters to {p}"
    except Exception as e:
        return format_tool_error("E_IO", f"Error writing file: {e}")


def _coerce_bounded_int(value: Any, default: int, maximum: int) -> int:
    try:
        number = int(value) if value not in (None, "None", "") else default
    except (ValueError, TypeError):
        number = default
    return max(1, min(number, maximum))


def _coerce_bool(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def tool_find_files(
    pattern: str = "**/*",
    path: str = ".",
    max_results: int = 200,
    workspace_root: Optional[str | Path] = None,
) -> str:
    """Find workspace files by glob and return workspace-relative paths."""
    root = _coerce_workspace_root(workspace_root)
    try:
        # For discovery tools, the default scope is the whole project
        # workspace rather than only the process's launch subdirectory.
        base = root if str(path or ".") in ("", ".") else check_workspace_jail(
            path, workspace_root=root
        )
    except PermissionError as pe:
        return format_tool_error("E_PERMISSION", str(pe), "Choose a path inside the project workspace.")
    if not base.exists():
        return format_tool_error("E_NOT_FOUND", f"Path '{path}' does not exist.")
    pattern = str(pattern or "**/*")
    limit = _coerce_bounded_int(max_results, 200, 1000)
    candidates = [base] if base.is_file() else _iter_workspace_files(root)
    matches: List[str] = []
    for candidate in candidates:
        try:
            rel_root = str(candidate.relative_to(root)).replace("\\", "/")
            rel_base = (
                candidate.name if base.is_file()
                else str(candidate.relative_to(base)).replace("\\", "/")
            )
        except ValueError:
            continue
        if _matches_glob(rel_root, pattern) or _matches_glob(rel_base, pattern):
            matches.append(rel_root)
    header = f"--- Files matching {pattern!r}: {len(matches)} in {root} ---\n"
    if not matches:
        return header + "No files matched."
    body = "\n".join(matches[:limit])
    if len(matches) > limit:
        body += f"\n... [truncated at {limit} of {len(matches)} files]"
    return header + body


def tool_search_code(
    query: str,
    path: str = ".",
    file_glob: Optional[str] = None,
    regex: bool = False,
    case_sensitive: bool = False,
    max_results: int = 50,
    context_lines: int = 0,
    workspace_root: Optional[str | Path] = None,
) -> str:
    """Search local text files for a literal or regex pattern."""
    query = "" if query is None else str(query)
    if not query:
        return format_tool_error("E_INVALID", "search_code requires a non-empty query.")
    root = _coerce_workspace_root(workspace_root)
    try:
        base = root if str(path or ".") in ("", ".") else check_workspace_jail(
            path, workspace_root=root
        )
    except PermissionError as pe:
        return format_tool_error("E_PERMISSION", str(pe), "Choose a path inside the project workspace.")
    if not base.exists():
        return format_tool_error("E_NOT_FOUND", f"Path '{path}' does not exist.")

    use_regex = _coerce_bool(regex)
    sensitive = _coerce_bool(case_sensitive)
    compiled = None
    if use_regex:
        try:
            compiled = re.compile(query, 0 if sensitive else re.IGNORECASE)
        except re.error as exc:
            return format_tool_error("E_INVALID", f"Invalid regex: {exc}")
    needle = query if sensitive else query.casefold()
    limit = _coerce_bounded_int(max_results, 50, 500)
    try:
        context = int(context_lines) if context_lines not in (None, "None", "") else 0
    except (ValueError, TypeError):
        context = 0
    context = max(0, min(context, 10))

    if base.is_file():
        rel_base = str(base.relative_to(root)).replace("\\", "/")
        if _is_sensitive_path(rel_base):
            return format_tool_error(
                "E_PERMISSION", "Credential-like files are excluded from code search."
            )
        candidates = [base]
    else:
        candidates = []
        for candidate in _iter_workspace_files(root):
            try:
                candidate.relative_to(base)
            except ValueError:
                continue
            candidates.append(candidate)

    rendered: List[str] = []
    files_scanned = 0
    match_count = 0
    truncated = False
    for candidate in candidates:
        rel = str(candidate.relative_to(root)).replace("\\", "/")
        if file_glob and not _matches_glob(rel, str(file_glob)):
            continue
        content = _read_text_file(candidate)
        if content is None:
            continue
        files_scanned += 1
        lines = content.splitlines()
        shown: Set[int] = set()
        for index, line in enumerate(lines, start=1):
            matched = bool(compiled.search(line)) if compiled else (
                needle in (line if sensitive else line.casefold())
            )
            if not matched:
                continue
            match_count += 1
            if match_count > limit:
                truncated = True
                continue
            start = max(1, index - context)
            end = min(len(lines), index + context)
            for number in range(start, end + 1):
                if number in shown:
                    continue
                shown.add(number)
                separator = ":" if number == index else "-"
                text = lines[number - 1][:300]
                rendered.append(f"{rel}:{number}{separator}{text}")

    header = (
        f"--- Code search: {match_count} matching line(s); "
        f"{files_scanned} text file(s) scanned in {root} ---\n"
    )
    if match_count == 0:
        return header + "No matches found."
    body = "\n".join(rendered)
    if truncated:
        body += f"\n... [truncated at {limit} matching lines]"
    return header + body


def tool_edit_file(
    path: str,
    old_text: str,
    new_text: str,
    replace_all: bool = False,
    workspace_root: Optional[str | Path] = None,
) -> str:
    """Replace exact text in a workspace file; unique match by default."""
    try:
        p = check_workspace_jail(path, workspace_root=workspace_root)
    except PermissionError as pe:
        return format_tool_error("E_PERMISSION", str(pe), "Choose a path inside the project workspace.")
    if not p.exists():
        return format_tool_error("E_NOT_FOUND", f"File '{path}' does not exist.")
    if not p.is_file():
        return format_tool_error("E_NOT_FILE", f"'{path}' is not a regular file.")
    old_text = "" if old_text is None else str(old_text)
    new_text = "" if new_text is None else str(new_text)
    if not old_text:
        return format_tool_error("E_INVALID", "edit_file requires non-empty old_text.")

    try:
        content = p.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        return format_tool_error("E_IO", f"Error reading file: {e}")
    occurrences = content.count(old_text)
    if occurrences == 0:
        return format_tool_error(
            "E_NOT_FOUND", f"old_text was not found in '{path}'; no changes made."
        )
    if occurrences > 1 and not _coerce_bool(replace_all):
        return format_tool_error(
            "E_AMBIGUOUS",
            f"old_text occurs {occurrences} times in '{path}'; "
            "provide a larger exact snippet or set replace_all=true.",
        )
    updated = content.replace(
        old_text, new_text, -1 if _coerce_bool(replace_all) else 1
    )
    trunc = detect_truncated_rewrite(content, updated)
    if trunc:
        return format_tool_error(
            "E_TRUNCATED_REWRITE",
            "Refused a likely truncated rewrite; no changes made.",
            "Re-read the file and apply a smaller, complete edit.",
        )
    try:
        p.write_text(updated, encoding="utf-8")
    except Exception as e:
        return format_tool_error("E_IO", f"Error writing file: {e}")
    replacements = occurrences if _coerce_bool(replace_all) else 1
    return (
        f"Successfully edited {p} "
        f"({replacements} replacement{'s' if replacements != 1 else ''})"
    )


def tool_registry_search(query: str, limit: int = 10) -> str:
    """Search the Program Registry database (~6,400 tools and programs)."""
    db_path = registry_db_path()
    if not db_path.exists():
        return f"Program registry database not found at {db_path}"

    try:
        try:
            limit = int(limit) if limit not in (None, "None", "") else 10
        except (ValueError, TypeError):
            limit = 10
        conn = sqlite3.connect(str(db_path))
        c = conn.cursor()
        # Query programs table
        c.execute(
            """
            SELECT id, name, category, description, path, is_critical
            FROM programs
            WHERE name LIKE ? OR description LIKE ? OR category LIKE ?
            LIMIT ?
            """,
            (f"%{query}%", f"%{query}%", f"%{query}%", limit),
        )
        rows = c.fetchall()
        conn.close()

        if not rows:
            return f"No programs or tools found matching '{query}' in registry."

        results = []
        for r in rows:
            results.append(
                f"• ID: {r[0]} | Name: {r[1]} | Category: {r[2]} | Path: {r[4] or 'N/A'}\n  Description: {r[3] or 'No description'}"
            )
        return f"Found {len(rows)} tools in Program Registry matching '{query}':\n" + "\n".join(results)
    except Exception as e:
        return f"Database query error: {e}"


TOOL_DEFINITIONS = [
    {
        "type": "function",
        "function": {
            "name": "bash",
            "description": "Execute a shell command in the local environment and return stdout, stderr, and exit code.",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "The exact shell command to run",
                    }
                },
                "required": ["command"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_directory",
            "description": "List files and subdirectories in a workspace folder (defaults to current folder '.').",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Absolute or relative folder path (default '.')", "default": "."},
                    "max_depth": {"type": "integer", "description": "Maximum directory traversal depth (default 2)", "default": 2},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "find_files",
            "description": "Find files in the local project workspace by glob pattern. Returns workspace-relative paths; default scope is the workspace root.",
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {"type": "string", "description": "Glob such as '*.py', '**/*.py', or 'src/**/*.ts' (default '**/*')", "default": "**/*"},
                    "path": {"type": "string", "description": "Workspace-relative folder or file to scope the search (default workspace root)", "default": "."},
                    "max_results": {"type": "integer", "description": "Max paths to return (default 200)", "default": 200},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_code",
            "description": "Search local project text/code files for a literal or regex pattern. Returns workspace-relative path:line matches. Use this to locate symbols and behavior before reading or editing.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Literal text or regex pattern to find"},
                    "path": {"type": "string", "description": "Workspace-relative file/folder to scope the search (default workspace root)", "default": "."},
                    "file_glob": {"type": "string", "description": "Optional filename/path glob filter such as '*.py'"},
                    "regex": {"type": "boolean", "description": "Treat query as regex (default false)", "default": False},
                    "case_sensitive": {"type": "boolean", "description": "Case-sensitive match (default false)", "default": False},
                    "context_lines": {"type": "integer", "description": "Context lines around each match (default 0)", "default": 0},
                    "max_results": {"type": "integer", "description": "Max matching lines (default 50)", "default": 50},
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read a numbered line range from a local workspace file. Line-number prefixes are display only; never include them when editing or writing.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Absolute or relative file path"},
                    "start_line": {"type": "integer", "description": "First 1-based line to return (default 1)", "default": 1},
                    "end_line": {"type": "integer", "description": "Last 1-based line to return (optional)"},
                    "max_lines": {"type": "integer", "description": "Max lines to return (default 300)", "default": 300},
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "write_file",
            "description": "Create or overwrite a file with given content.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File path to write"},
                    "content": {"type": "string", "description": "Full file content to write"},
                },
                "required": ["path", "content"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "edit_file",
            "description": "Replace exact text in an existing workspace file. Requires a unique exact match unless replace_all is true. Prefer this for targeted code changes; do not include read_file line-number prefixes in old_text or new_text.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File path to edit"},
                    "old_text": {"type": "string", "description": "Exact existing text to replace"},
                    "new_text": {"type": "string", "description": "Replacement text"},
                    "replace_all": {"type": "boolean", "description": "Replace every occurrence (default false)", "default": False},
                },
                "required": ["path", "old_text", "new_text"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "registry_search",
            "description": "Search the local Program Registry database containing over 6,400 system tools, binaries, and dependencies.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Tool name, keyword, or category to search for",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of results to return (default 10)",
                    },
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "consult_provider",
            "description": "Delegate a sub-task or question to another AI provider (e.g. ask NVIDIA NIM for CUDA/high-end reasoning, XKiro for Minimax/Grok, or OpenRouter for diverse models).",
            "parameters": {
                "type": "object",
                "properties": {
                    "provider": {
                        "type": "string",
                        "description": "Target provider: 'groq', 'openrouter', 'nvidia', 'cloudflare', 'bynara', 'apinex', or 'xkiro'",
                    },
                    "model": {
                        "type": "string",
                        "description": "Model ID to use on the target provider (optional, uses default if omitted)",
                    },
                    "prompt": {
                        "type": "string",
                        "description": "The specific query, task, or code snippet to ask the other provider",
                    },
                },
                "required": ["provider", "prompt"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "verify_http",
            "description": "Deterministically verify an HTTP endpoint behavior against an Expected prediction string (status code, body predicates, header requirements). Returns strict binary CONFIRMED or REJECTED verdict.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target HTTP/HTTPS URL"},
                    "method": {
                        "type": "string",
                        "description": "HTTP method. GET, HEAD, and OPTIONS are allowed by default; mutating methods require operator opt-in.",
                        "default": "GET",
                    },
                    "expected": {
                        "type": "string",
                        "description": "Required, parseable prediction, e.g.: 'status 200, body contains \"user_id\", header x-frame-options absent'",
                        "minLength": 1,
                    },
                    "body": {"type": "string", "description": "Optional request body"},
                },
                "required": ["url", "expected"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "verify_code",
            "description": "Deterministically verify source code patterns or security guards in local files. Inspects AST/code for required authorization checks or forbidden sinks.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Path to local code file to inspect"},
                    "must_contain": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Exact literal source-code substrings that MUST be present (not semantic labels)",
                    },
                    "must_not_contain": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Exact literal source-code substrings that MUST be absent; a failed check does not prove the inverse security claim",
                    },
                    "target_function": {"type": "string", "description": "Optional function name to scope inspection"},
                    "check_type": {
                        "type": "string",
                        "description": "Optional built-in check type (e.g. 'wp_auth_check')",
                    },
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "analyze_python_security",
            "description": "Run a bounded Python AST analysis for function-parameter or request-derived values interpolated into SQL execution sinks. Reports source-level candidates only, not confirmed vulnerabilities.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Python source file inside the current workspace"},
                    "target_function": {"type": "string", "description": "Optional function name to scope analysis"},
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "verify_consensus",
            "description": "Run blind verification consensus across multiple AI models / model families (same API key or cross-provider) to corroboratively validate or reject a security hypothesis.",
            "parameters": {
                "type": "object",
                "properties": {
                    "claim": {"type": "string", "description": "The specific vulnerability or behavior claim to evaluate"},
                    "evidence": {"type": "string", "description": "Code snippet, HTTP trace, or execution evidence"},
                    "models": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Optional list of provider:model specs (e.g. ['cloudflare:@cf/meta/llama-3.3-70b-instruct-fp8-fast', 'cloudflare:@cf/qwen/qwen2.5-coder-32b-instruct', 'nvidia:meta/llama-3.2-11b-vision-instruct'])",
                    },
                },
                "required": ["claim", "evidence"],
            },
        },
    },
]


def execute_tool_call(
    tool_name: str,
    arguments: Dict[str, Any],
    client_ref: Any = None,
    allow_shell: bool = False,
    allow_local: bool = False,
    allowed_hosts: Optional[List[str]] = None,
    allow_mutating_http: bool = False,
    workspace_root: Optional[str | Path] = None,
) -> str:
    """Execute a function call by name and arguments."""
    arguments = arguments if isinstance(arguments, dict) else {}
    if tool_name == "bash":
        return tool_bash(
            command=arguments.get("command", ""),
            timeout=arguments.get("timeout", 30),
            allow_shell=allow_shell,
            workspace_root=workspace_root,
        )
    elif tool_name == "list_directory":
        return tool_list_directory(
            path=arguments.get("path", "."),
            max_depth=arguments.get("max_depth", 2),
            workspace_root=workspace_root,
        )
    elif tool_name == "find_files":
        return tool_find_files(
            pattern=arguments.get("pattern", "**/*"),
            path=arguments.get("path", "."),
            max_results=arguments.get("max_results", 200),
            workspace_root=workspace_root,
        )
    elif tool_name == "search_code":
        return tool_search_code(
            query=arguments.get("query", ""),
            path=arguments.get("path", "."),
            file_glob=arguments.get("file_glob") or arguments.get("glob"),
            regex=arguments.get("regex", False),
            case_sensitive=arguments.get("case_sensitive", False),
            max_results=arguments.get("max_results", 50),
            context_lines=arguments.get("context_lines", 0),
            workspace_root=workspace_root,
        )
    elif tool_name == "read_file":
        return tool_read_file(
            path=arguments.get("path", ""),
            max_lines=arguments.get("max_lines", 300),
            start_line=arguments.get("start_line", 1),
            end_line=arguments.get("end_line"),
            workspace_root=workspace_root,
        )
    elif tool_name == "write_file":
        return tool_write_file(
            path=arguments.get("path", ""),
            content=arguments.get("content", ""),
            workspace_root=workspace_root,
        )
    elif tool_name == "edit_file":
        return tool_edit_file(
            path=arguments.get("path", ""),
            old_text=arguments.get("old_text", ""),
            new_text=arguments.get("new_text", ""),
            replace_all=arguments.get("replace_all", False),
            workspace_root=workspace_root,
        )
    elif tool_name == "registry_search":
        return tool_registry_search(query=arguments.get("query", ""), limit=arguments.get("limit", 10))
    elif tool_name == "verify_http":
        return tool_verify_http(
            url=arguments.get("url", ""),
            method=arguments.get("method", "GET"),
            headers=arguments.get("headers"),
            body=arguments.get("body"),
            expected=arguments.get("expected", ""),
            allow_local=allow_local,
            allowed_hosts=allowed_hosts,
            allow_mutating_http=allow_mutating_http,
        )
    elif tool_name == "verify_code":
        return tool_verify_code(
            path=arguments.get("path", ""),
            must_contain=arguments.get("must_contain"),
            must_not_contain=arguments.get("must_not_contain"),
            target_function=arguments.get("target_function"),
            check_type=arguments.get("check_type"),
            workspace_root=workspace_root,
        )
    elif tool_name == "analyze_python_security":
        return tool_analyze_python_security(
            path=arguments.get("path", ""),
            target_function=arguments.get("target_function"),
            workspace_root=workspace_root,
        )
    elif tool_name == "verify_consensus":
        return tool_verify_consensus(
            claim=arguments.get("claim", ""),
            evidence=arguments.get("evidence", ""),
            models=arguments.get("models"),
            client_ref=client_ref,
        )
    elif tool_name == "consult_provider":
        if client_ref is None:
            return "Error: Client reference not provided to execute cross-provider consultation."
        provider = arguments.get("provider", "openrouter").lower()
        model = arguments.get("model")
        prompt = arguments.get("prompt", "")
        try:
            res = client_ref.chat_complete(
                provider_id=provider,
                messages=[
                    {"role": "system", "content": "You are a specialized expert model providing a direct, precise answer."},
                    {"role": "user", "content": prompt},
                ],
                model=model,
                max_tokens=2048,
            )
            choices = res.get("choices", [])
            if choices:
                return f"[{provider.upper()} RESPONSE]:\n" + choices[0]["message"]["content"]
            return f"[{provider.upper()} RESPONSE]: No content returned."
        except Exception as e:
            return f"Error consulting {provider}: {e}"
    else:
        return f"Unknown tool: '{tool_name}'"
