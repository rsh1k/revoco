"""recoup — containment and recovery control plane for AI agents.

The Python half. It owns everything that needs to read the world or think about
it: compiling policy, classifying reversibility from live state, running drills,
building evidence. The Go half in `cmd/recoup-enforcer` owns the request path and
nothing else.

See `contract/README.md` for where the line is drawn and why.
"""

from .bundle import (
    SCHEMA,
    BundleError,
    Call,
    Verdict,
    classify,
    compile_bundle,
    dumps,
    evaluate,
)

__all__ = [
    "SCHEMA", "BundleError", "Call", "Verdict",
    "classify", "compile_bundle", "dumps", "evaluate",
]
__version__ = "0.1.0"
