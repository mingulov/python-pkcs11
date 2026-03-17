"""
:mod:`pkcs11` defines a high-level, "Pythonic" interface to PKCS#11.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from pkcs11.constants import *  # noqa: F403
from pkcs11.exceptions import *  # noqa: F403
from pkcs11.mechanisms import *  # noqa: F403
from pkcs11.types import *  # noqa: F403
from pkcs11.util import dh, dsa, ec, rsa, x509  # noqa: F401

if TYPE_CHECKING:
    from pkcs11._pkcs11 import lib as _lib_type


_loaded: dict[str, Any] = {}


def lib(so: str, interface: str = "auto") -> _lib_type:
    """
    Wrap the main library call coming from Cython with a preemptive
    dynamic loading.

    :param so: Path to the PKCS#11 shared library.
    :param interface: Requested interface version: ``"auto"`` (default),
        ``"2.40"``, ``"3.0"``, ``"3.1"``, or ``"3.2"``.
    """
    global _loaded

    # Cache key includes the requested interface so different interface
    # versions of the same library are loaded as separate instances.
    cache_key = f"{so}:{interface}"

    try:
        _lib = _loaded[cache_key]
        if not _lib.initialized:
            _lib.initialize()
        return _lib
    except KeyError:
        pass

    from . import _pkcs11

    _lib = _pkcs11.lib(so, interface=interface)
    _loaded[cache_key] = _lib

    return _lib


def unload(so: str) -> None:
    global _loaded
    try:
        loaded_lib = _loaded[so]
    except KeyError:
        return
    del _loaded[so]
    loaded_lib.unload()
