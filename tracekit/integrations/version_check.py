"""The version check the hand-wired integrations share.

`tracekit.instrument()` warns for the frameworks it wires itself: a version outside the tested range is wired but
untested. The five integrations built by hand (Microsoft Agent Framework, Google ADK, Haystack, LlamaIndex, Strands
Agents) got no such warning, so a framework minor that moved a hook or changed a callback's arguments failed in ways
that were hard to trace back to the version. This module holds the one check they share: it reads the installed
version and warns, once per process, when it is outside the range Tracekit is tested with.
"""
import threading
import warnings

from tracekit.autowire import _release, _untested_warning, _version

_LOCK = threading.Lock()
_WARNED = set()   # the frameworks already warned about, this process


def warn_untested(label, dist, lo, hi, req):
    """Warn (once per process) that the framework `label` is installed at a version Tracekit is not tested with.

    `dist` is the distribution whose installed version is read, `lo` and `hi` the release tuples of the versions
    Tracekit is tested with (as `tracekit.instrument()` compares them), and `req` the pip requirement naming them. A
    version that can't be read (the distribution is not installed, or its metadata is unreadable) means no warning:
    this never raises.
    """
    try:
        version = _version(dist)
        if version is None:
            return
        if lo <= _release(version) < hi:
            return
    except Exception:
        return
    with _LOCK:
        if label in _WARNED:
            return
        _WARNED.add(label)
    warnings.warn(f"tracekit: {_untested_warning(label, version, req)}", stacklevel=3)
