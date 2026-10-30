"""Auto-generated seam check for S018.

Exit 0 = claim holds (no seam), 1 = seam confirmed, 2 = inconclusive.
"""
import importlib
import inspect
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
for _p in (REPO, REPO / "src"):
    if _p.is_dir():
        sys.path.insert(0, str(_p))

KIND = 'type-hint'
MODULE = 'oracle.oracle_mindset_context'
FUNC = '_program_brief'
EXC = None
EXPECTED = None
CLAIM_FILE = None  # doc file holding the claim (repo-relative), None = docstring
CLAIM_LINE = 0
CLAIM_RE = None


def _done(code, label, reason):
    print(f"{label}: {reason}")
    sys.exit(code)


def _claim_still_made(fn):
    """Re-reads the claim where it lives now: the doc line, or the live docstring."""
    if CLAIM_FILE is not None:
        lines = (REPO / CLAIM_FILE).read_text(encoding="utf-8").splitlines()
        text = lines[CLAIM_LINE - 1] if 0 < CLAIM_LINE <= len(lines) else ""
    else:
        text = inspect.getdoc(fn) or ""
    return re.search(CLAIM_RE, text, re.IGNORECASE) is not None


def _ann_name(ann):
    if ann is inspect.Parameter.empty or ann is inspect.Signature.empty:
        return ""
    return ann if isinstance(ann, str) else getattr(ann, "__name__", repr(ann))


def _arg_for(ann):
    name = _ann_name(ann).replace(" ", "")
    if name.startswith("dict"):
        return {}
    if name == "str":
        return ""
    if name.startswith("list"):
        return []
    return None


def main():
    try:
        fn = getattr(importlib.import_module(MODULE), FUNC)
    except Exception as e:
        _done(2, "INCONCLUSIVE", f"cannot import {MODULE}.{FUNC}: {e}")

    sig = inspect.signature(fn)
    args = [
        _arg_for(p.annotation)
        for p in sig.parameters.values()
        if p.default is inspect.Parameter.empty
        and p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)
    ]

    if KIND == "type-hint":
        ann = _ann_name(sig.return_annotation).replace(" ", "")
        if ann in ("", "object", "Any") or "None" in ann or "Optional" in ann:
            _done(0, "HOLDS", f"{FUNC} return annotation {ann or 'missing'} allows None")
        try:
            result = fn(*args)
        except Exception as e:
            _done(2, "INCONCLUSIVE", f"{FUNC}{tuple(args)} raised {type(e).__name__}: {e}")
        if result is None:
            _done(1, "CONFIRMED", f"{FUNC}{tuple(args)} returned None, annotation says {ann}")
        _done(0, "HOLDS", f"{FUNC}{tuple(args)} returned {type(result).__name__}")

    if KIND == "raises":
        if not _claim_still_made(fn):
            _done(0, "HOLDS", f"the docs no longer claim {FUNC} raises {EXC}")
        try:
            fn(*args)
        except Exception as e:
            if type(e).__name__ == EXC:
                _done(0, "HOLDS", f"{FUNC}{tuple(args)} raised {EXC} as documented")
            _done(2, "INCONCLUSIVE", f"{FUNC}{tuple(args)} raised {type(e).__name__}, not {EXC}")
        _done(1, "CONFIRMED", f"{FUNC}{tuple(args)} returned normally; docs say it raises {EXC}")

    if KIND == "never-none":
        if not _claim_still_made(fn):
            _done(0, "HOLDS", f"the docs no longer claim {FUNC} never returns None")
        try:
            result = fn(*args)
        except Exception as e:
            _done(2, "INCONCLUSIVE", f"{FUNC}{tuple(args)} raised {type(e).__name__}: {e}")
        if result is None:
            _done(1, "CONFIRMED", f"{FUNC}{tuple(args)} returned None; docs say it never does")
        _done(0, "HOLDS", f"{FUNC}{tuple(args)} returned {type(result).__name__}, not None")

    if KIND == "config-required":
        try:
            value = fn({})
        except (KeyError, ValueError) as e:
            _done(0, "HOLDS", f"{FUNC}({{}}) raised {type(e).__name__}: field is enforced")
        except Exception as e:
            _done(2, "INCONCLUSIVE", f"{FUNC}({{}}) raised {type(e).__name__}: {e}")
        _done(1, "CONFIRMED", f"{FUNC}({{}}) returned {value!r} instead of failing")

    if KIND == "config-default":
        try:
            value = fn({})
        except Exception as e:
            _done(2, "INCONCLUSIVE", f"{FUNC}({{}}) raised {type(e).__name__}: {e}")
        if value == EXPECTED:
            _done(0, "HOLDS", f"{FUNC}({{}}) returned schema default {EXPECTED!r}")
        _done(1, "CONFIRMED", f"{FUNC}({{}}) returned {value!r}, schema default is {EXPECTED!r}")

    _done(2, "INCONCLUSIVE", f"unknown check kind {KIND}")


# Any crash is inconclusive. It must never fall through to exit 1 (= confirmed).
try:
    main()
except SystemExit:
    raise
except BaseException as e:
    _done(2, "INCONCLUSIVE", f"check crashed: {type(e).__name__}: {e}")
