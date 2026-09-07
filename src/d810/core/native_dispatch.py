"""Runtime-independent eligibility for native pointer dispatch."""


def supports_native_pointer(value: object, native_type: type) -> bool:
    """Require the vendor wrapper and its pointer before selecting native code."""
    return isinstance(value, native_type) and getattr(value, "this", None) is not None
