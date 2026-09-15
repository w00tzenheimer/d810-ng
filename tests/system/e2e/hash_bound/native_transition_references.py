"""Hand-checked native transition slices for the hash-bound fixtures."""

from __future__ import annotations

from tests.system.e2e.hash_bound.native_transition_oracle import (
    NativeImageSlice,
    NativeInstruction,
    NativeTransitionRequest,
)


def _instructions(
    image_base: int, rows: tuple[tuple[int, str], ...]
) -> tuple[NativeInstruction, ...]:
    return tuple(
        NativeInstruction(image_base + rva, bytes.fromhex(encoded))
        for rva, encoded in rows
    )


def _request(
    *,
    image_base: int,
    rows: tuple[tuple[int, str], ...],
    entry_rva: int,
    target_rvas: tuple[tuple[str, tuple[int, ...]], ...],
    selector_stack_offset: int,
    target_observation_rva: int | None = None,
    extra_register_assumptions: tuple[tuple[str, int], ...] = (),
    extra_memory_assumptions: tuple[tuple[int, bytes], ...] = (),
) -> NativeTransitionRequest:
    return NativeTransitionRequest(
        instructions=_instructions(image_base, rows),
        entry_ea=image_base + entry_rva,
        target_partitions=tuple(
            (name, tuple(image_base + rva for rva in rvas))
            for name, rvas in target_rvas
        ),
        register_assumptions=(("rsp", 0x70008000), *extra_register_assumptions),
        memory_assumptions=((0x70007000, bytes(0x2000)), *extra_memory_assumptions),
        instruction_budget=64,
        target_observation_ea=(
            None
            if target_observation_rva is None
            else image_base + target_observation_rva
        ),
        selector_observation=(0x70008000 + selector_stack_offset, 4),
    )


_E1_DISPATCH_PREFIX = (
    (0x98E06, "448b4c2404"),
    (0x98E0B, "4181f92a908e6e"),
    (0x98E12, "7557"),
)
_E1_DISPATCH_TAIL = (
    (0x98E6B, "4181f9b7799a19"),
    (0x98E72, "7508"),
)


def e1e69e0_native_slices(image_base: int) -> tuple[NativeImageSlice, ...]:
    """Return the three independently checked selector routes in E1E69E0."""

    initial = _request(
        image_base=image_base,
        rows=(
            (0x98D88, "8b15a6780300"),
            (0x98D8E, "448d8ab7b20b37"),
            (0x98D95, "448d92290710a2"),
            (0x98D9C, "81c2f8c36398"),
            (0x98DA2, "4433d2"),
            (0x98DA5, "81f2d384a835"),
            (0x98DAB, "448d9adf854342"),
            (0x98DB2, "4533da"),
            (0x98DB5, "4181f39c519a83"),
            (0x98DBC, "4181c3c5659b31"),
            (0x98DC3, "4133d1"),
            (0x98DC6, "4133d3"),
            (0x98DC9, "89542404"),
            (0x98DCD, "ffc9"),
            (0x98DCF, "488d159affffff"),
            (0x98DD6, "eb2e"),
            *_E1_DISPATCH_PREFIX,
        ),
        entry_rva=0x98D88,
        target_rvas=(("state_6e8e902a", (0x98E14,)),),
        selector_stack_offset=4,
    )
    atomic = _request(
        image_base=image_base,
        rows=(
            (0x98DD8, "448b0d51780300"),
            (0x98DDF, "458d916b66793d"),
            (0x98DE6, "458d99ac080407"),
            (0x98DED, "4533da"),
            (0x98DF0, "4181c12f559128"),
            (0x98DF7, "4533cb"),
            (0x98DFA, "4181f1bffcdb63"),
            (0x98E01, "44894c2404"),
            *_E1_DISPATCH_PREFIX,
            *_E1_DISPATCH_TAIL,
        ),
        entry_rva=0x98DD8,
        target_rvas=(
            ("atomic_lock_seto", (0x98E74,)),
            ("return", (0x98E7C,)),
        ),
        selector_stack_offset=4,
    )
    terminal = _request(
        image_base=image_base,
        rows=(
            (0x98E2F, "448b0d02780300"),
            (0x98E36, "458d91e3ef3e98"),
            (0x98E3D, "4181f220832b59"),
            (0x98E44, "458d9ac3d8bae0"),
            (0x98E4B, "418db2b68e21b5"),
            (0x98E52, "bfe7c4765b"),
            (0x98E57, "412bf9"),
            (0x98E5A, "4133f9"),
            (0x98E5D, "33fe"),
            (0x98E5F, "4133fb"),
            (0x98E62, "4103fa"),
            (0x98E65, "897c2404"),
            (0x98E69, "eb9b"),
            *_E1_DISPATCH_PREFIX,
            *_E1_DISPATCH_TAIL,
        ),
        entry_rva=0x98E2F,
        target_rvas=(("return", (0x98E7C,)),),
        selector_stack_offset=4,
    )
    return (
        NativeImageSlice(
            image_base=image_base,
            request=initial,
            linked_memory=((image_base + 0xD0634, bytes.fromhex("72dde581")),),
        ),
        NativeImageSlice(
            image_base=image_base,
            request=atomic,
            linked_memory=((image_base + 0xD0630, bytes.fromhex("20926508")),),
        ),
        NativeImageSlice(
            image_base=image_base,
            request=terminal,
            linked_memory=((image_base + 0xD0638, bytes.fromhex("7d9a460f")),),
        ),
    )


_E086_DISPATCH_HIGH = (
    (0x86B0B, "8b442448"),
    (0x86B0F, "3d5258814c"),
    (0x86B14, "0f8fe7010000"),
    (0x86D01, "3d982f646e"),
    (0x86D06, "0f8f8e380000"),
)


def e086be0_missing_native_slices(image_base: int) -> tuple[NativeImageSlice, ...]:
    """Return exact native proofs for five routes omitted by the old golden."""

    references = (
        (
            _request(
                image_base=image_base,
                rows=(
                    (0x8AA1A, "8b05855a0400"),
                    (0x8AA20, "8d881706dc00"),
                    (0x8AA26, "8d903d4e44bb"),
                    (0x8AA2C, "81f21b26d199"),
                    (0x8AA32, "81c225fb0e1a"),
                    (0x8AA38, "33c8"),
                    (0x8AA3A, "33ca"),
                    (0x8AA3C, "03c1"),
                    (0x8AA3E, "053d4e44bb"),
                    (0x8AA43, "89442448"),
                    (0x8AA47, "e9bfc0ffff"),
                    *_E086_DISPATCH_HIGH,
                    (0x8A59A, "3d79679176"),
                    (0x8A59F, "0f8e42030000"),
                    (0x8A5A5, "3d7a679176"),
                    (0x8A5AA, "0f8424040000"),
                    (0x8A5B0, "3d69c9cc7a"),
                    (0x8A5B5, "0f859b070000"),
                ),
                entry_rva=0x8AA1A,
                target_rvas=(("handler_8A5BB", (0x8A5BB,)),),
                selector_stack_offset=0x48,
                target_observation_rva=0x8AA43,
            ),
            0xD04A5,
            "e52ed540",
        ),
        (
            _request(
                image_base=image_base,
                rows=(
                    (0x8C942, "8b05693b0400"),
                    (0x8C948, "8bc8"),
                    (0x8C94A, "81f17b7584a8"),
                    (0x8C950, "8d91af41b255"),
                    (0x8C956, "81f2a6ecf83a"),
                    (0x8C95C, "2bd1"),
                    (0x8C95E, "2bd0"),
                    (0x8C960, "8d040a"),
                    (0x8C963, "05b8d899b2"),
                    (0x8C968, "89442448"),
                    (0x8C96C, "e99aa1ffff"),
                    *_E086_DISPATCH_HIGH,
                    (0x8A59A, "3d79679176"),
                    (0x8A59F, "0f8e42030000"),
                    (0x8A8E7, "3d992f646e"),
                    (0x8A8EC, "0f85e3060000"),
                ),
                entry_rva=0x8C942,
                target_rvas=(("handler_8AFD5", (0x8AFD5,)),),
                selector_stack_offset=0x48,
                target_observation_rva=0x8C968,
            ),
            0xD04B1,
            "6f8effe1",
        ),
        (
            _request(
                image_base=image_base,
                rows=(
                    (0x8CC1D, "8b05b2380400"),
                    (0x8CC23, "8d88806a41fd"),
                    (0x8CC29, "81f11c6544a7"),
                    (0x8CC2F, "03c1"),
                    (0x8CC31, "05806a41fd"),
                    (0x8CC36, "03c1"),
                    (0x8CC38, "051dbc4edb"),
                    (0x8CC3D, "89442448"),
                    (0x8CC41, "e9c59effff"),
                    *_E086_DISPATCH_HIGH,
                    (0x86D0C, "3d31e0fa51"),
                    (0x86D11, "0f8e8e3b0000"),
                    (0x86D17, "3d32e0fa51"),
                    (0x86D1C, "0f84663c0000"),
                ),
                entry_rva=0x8CC1D,
                target_rvas=(("handler_8A988", (0x8A988,)),),
                selector_stack_offset=0x48,
                target_observation_rva=0x8CC3D,
            ),
            0xD04D5,
            "2f5e253b",
        ),
        (
            _request(
                image_base=image_base,
                rows=(
                    (0x8D530, "8b058f2f0400"),
                    (0x8D536, "8d882abd2f36"),
                    (0x8D53C, "8d9015ecea65"),
                    (0x8D542, "81f2a9ec3bfa"),
                    (0x8D548, "448d0410"),
                    (0x8D54C, "4181c066b5e7c1"),
                    (0x8D553, "4433c1"),
                    (0x8D556, "428d0c00"),
                    (0x8D55A, "81c146447f2f"),
                    (0x8D560, "33c8"),
                    (0x8D562, "2bca"),
                    (0x8D564, "81c181523600"),
                    (0x8D56A, "894c2448"),
                    (0x8D56E, "e99895ffff"),
                    *_E086_DISPATCH_HIGH,
                    (0x8A59A, "3d79679176"),
                    (0x8A59F, "0f8e42030000"),
                    (0x8A5A5, "3d7a679176"),
                    (0x8A5AA, "0f8424040000"),
                    (0x8A5B0, "3d69c9cc7a"),
                    (0x8A5B5, "0f859b070000"),
                ),
                entry_rva=0x8D530,
                target_rvas=(("handler_8AD56", (0x8AD56,)),),
                selector_stack_offset=0x48,
                target_observation_rva=0x8D56A,
            ),
            0xD04C5,
            "d84e5ac8",
        ),
        (
            _request(
                image_base=image_base,
                rows=(
                    (0x8EB36, "8b0559190400"),
                    (0x8EB3C, "8bc8"),
                    (0x8EB3E, "81f1214f482d"),
                    (0x8EB44, "8d912ef14c06"),
                    (0x8EB4A, "448bc1"),
                    (0x8EB4D, "4433c2"),
                    (0x8EB50, "81f24db16486"),
                    (0x8EB56, "03ca"),
                    (0x8EB58, "81c115cfd6d0"),
                    (0x8EB5E, "03ca"),
                    (0x8EB60, "81c115cfd6d0"),
                    (0x8EB66, "03ca"),
                    (0x8EB68, "2bc8"),
                    (0x8EB6A, "81c149e8bd1b"),
                    (0x8EB70, "4133c8"),
                    (0x8EB73, "894c2448"),
                    (0x8EB77, "e98f7fffff"),
                    *_E086_DISPATCH_HIGH,
                    (0x86D0C, "3d31e0fa51"),
                    (0x86D11, "0f8e8e3b0000"),
                    (0x8A8A5, "3d5358814c"),
                    (0x8A8AA, "0f859f050000"),
                ),
                entry_rva=0x8EB36,
                target_rvas=(("handler_8A8B0", (0x8A8B0,)),),
                selector_stack_offset=0x48,
                target_observation_rva=0x8EB73,
            ),
            0xD0495,
            "1bc69c14",
        ),
    )
    return tuple(
        NativeImageSlice(
            image_base=image_base,
            request=request,
            linked_memory=((image_base + linked_rva, bytes.fromhex(linked_hex)),),
        )
        for request, linked_rva, linked_hex in references
    )


def e086be0_gs_selector_slice(image_base: int) -> NativeImageSlice:
    """Prove the 0x8EC5D arm under an explicit Windows GS-base assumption."""

    return NativeImageSlice(
        image_base=image_base,
        request=_request(
            image_base=image_base,
            rows=(
                (0x8EC5D, "65488b042560000000"),
                (0x8EC66, "4883c018"),
                (0x8EC6A, "4889842430010000"),
                (0x8EC72, "8b0529180400"),
                (0x8EC78, "8d881a7c0890"),
                (0x8EC7E, "8d90a79dfc79"),
                (0x8EC84, "448d80c2ff850a"),
                (0x8EC8B, "4433c2"),
                (0x8EC8E, "8d90df061183"),
                (0x8EC94, "448d886e64fa40"),
                (0x8EC9B, "4433c9"),
                (0x8EC9E, "81f2161c58b9"),
                (0x8ECA4, "8d0c10"),
                (0x8ECA7, "81c1e28060bf"),
                (0x8ECAD, "4133c8"),
                (0x8ECB0, "03c1"),
                (0x8ECB2, "056e64fa40"),
                (0x8ECB7, "4133c1"),
                (0x8ECBA, "350a0664c0"),
                (0x8ECBF, "89442448"),
                (0x8ECC3, "4c8ba424f8000000"),
            ),
            entry_rva=0x8EC5D,
            target_rvas=(("selector_3076403d", (0x8ECC3,)),),
            selector_stack_offset=0x48,
            target_observation_rva=0x8ECBF,
            extra_register_assumptions=(("gs_base", 0x71000000),),
            extra_memory_assumptions=(
                (0x71000060, (0x12345000).to_bytes(8, "little")),
            ),
        ),
        linked_memory=((image_base + 0xD04A1, bytes.fromhex("5718dd4c")),),
    )


__all__ = [
    "e086be0_gs_selector_slice",
    "e086be0_missing_native_slices",
    "e1e69e0_native_slices",
]
