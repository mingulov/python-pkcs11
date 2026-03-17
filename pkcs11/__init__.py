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


_loaded: dict[tuple[str, str], Any] = {}


def _is_compatible_request(loaded_lib: Any, interface: str) -> bool:
    if interface == "auto":
        return True

    return loaded_lib.interface_version == interface


def lib(so: str, interface: str = "auto") -> _lib_type:
    """
    Wrap the main library call coming from Cython with a preemptive
    dynamic loading.

    :param so: Path to the PKCS#11 shared library.
    :param interface: Requested interface version: ``"auto"`` (default),
        ``"2.40"``, ``"3.0"``, ``"3.1"``, or ``"3.2"``.
    """
    global _loaded

    # Cache by requested interface, but reuse a compatible live instance for
    # the same module so we don't try to initialize the same PKCS#11 library
    # twice in one process.
    cache_key = (so, interface)

    try:
        _lib = _loaded[cache_key]
        if not _lib.initialized:
            _lib.initialize()
        return _lib
    except KeyError:
        pass

    for loaded_key, loaded_lib in _loaded.items():
        if loaded_key[0] != so:
            continue
        if not _is_compatible_request(loaded_lib, interface):
            raise RuntimeError(
                f"{so} is already loaded with interface {loaded_lib.interface_version}; "
                f"unload it before requesting interface {interface}"
            )
        if not loaded_lib.initialized:
            loaded_lib.initialize()
        _loaded[cache_key] = loaded_lib
        return loaded_lib

    from . import _pkcs11

    _lib = _pkcs11.lib(so, interface=interface)
    _loaded[cache_key] = _lib

    return _lib


def unload(so: str) -> None:
    global _loaded

    cache_keys = [key for key in _loaded if key[0] == so]
    if not cache_keys:
        return

    unloaded = set()
    for cache_key in cache_keys:
        loaded_lib = _loaded.pop(cache_key)
        if id(loaded_lib) in unloaded:
            continue
        loaded_lib.unload()
        unloaded.add(id(loaded_lib))
