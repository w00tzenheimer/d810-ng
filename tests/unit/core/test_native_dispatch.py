"""Native dispatch is testable without loading the IDA runtime."""

from d810.core.native_dispatch import supports_native_pointer


class _Native:
    pass


def test_scalar_double_does_not_enter_native_pointer_path():
    class Scalar:
        t = 1
        this = object()

    assert not supports_native_pointer(Scalar(), _Native)
    assert not supports_native_pointer(_Native(), _Native)


def test_native_wrapper_requires_pointer_attribute():
    native = _Native()
    native.this = object()
    assert supports_native_pointer(native, _Native)
    native.this = None
    assert not supports_native_pointer(native, _Native)
