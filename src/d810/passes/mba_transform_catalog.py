"""Checked-in config-v2 operator metadata for ``mba-simplify``.

This catalog deliberately owns every family assignment.  The UI must never
derive an operator family from a transform identifier or a rule class name.
"""

from __future__ import annotations

from d810.core.pass_editor_spec import (
    AdvisoryTone,
    PassEditorSpec,
    TransformCost,
    TransformEditorSpec,
    VerificationStatus,
)
from d810.passes.mba_transform_options import (
    MBA_TRANSFORM_OPTION_FIELDS,
    mba_transform_stages,
)


_FAMILY_MEMBERSHIP: tuple[tuple[str, str, str, str, tuple[str, ...]], ...] = (
    (
        "arithmetic",
        "Arithmetic",
        "addition",
        "Addition",
        (
            "add-xor-1", "add-xor-2", "add-hackers-delight-1",
            "add-hackers-delight-2", "add-hackers-delight-3",
            "add-hackers-delight-4", "add-hackers-delight-5", "add-ollvm-1",
            "add-ollvm-2", "add-ollvm-3", "add-ollvm-4",
            "add-ollvm-dynamic-const", "add-special-constant-1",
            "add-special-constant-2", "add-special-constant-3",
        ),
    ),
    (
        "boolean",
        "Boolean algebra",
        "and",
        "AND",
        (
            "and-1-mba-1", "and-bnot-factor-1", "and-bnot-factor-2",
            "and-bnot-factor-3", "and-bnot-factor-4",
            "and-bnot-hackers-delight-1", "and-bnot-hackers-delight-2",
            "and-chain", "and-get-upper-bits-factor-1", "and-or-factor-1",
            "and-xor-factor-1", "and-factor-1", "and-factor-2",
            "and-hackers-delight-1", "and-hackers-delight-2",
            "and-hackers-delight-3", "and-hackers-delight-4", "and-ollvm-1",
            "and-ollvm-2", "and-ollvm-3",
        ),
    ),
    (
        "analysis",
        "Analysis and normalization",
        "arithmetic-chain",
        "Arithmetic chains",
        ("arithmetic-chain",),
    ),
    (
        "boolean",
        "Boolean algebra",
        "not",
        "NOT and bnot",
        (
            "bnot-add-mba-1", "bnot-and-factor-1", "bnot-and-factor-2",
            "bnot-and-factor-3", "bnot-and-factor-4", "bnot-or-factor-1",
            "bnot-xor-factor-1", "bnot-xor-paired-not-1", "bnot-xor-2",
            "bnot-xor-3", "bnot-factor-1", "bnot-factor-2", "bnot-factor-3",
            "bnot-factor-4", "bnot-factor-5", "bnot-hackers-delight-1",
            "bnot-hackers-delight-2", "bnot-hodur-1", "bnot-mba-1", "bnot-1",
            "bnot-xor-demorgan-1",
        ),
    ),
    (
        "constants",
        "Constants",
        "constant-folding",
        "Constant folding",
        (
            "constant-call-result-fold", "cst-simplification-1",
            "cst-simplification-10", "cst-simplification-11",
            "cst-simplification-12", "cst-simplification-13",
            "cst-simplification-14", "cst-simplification-15",
            "cst-simplification-16", "cst-simplification-17",
            "cst-simplification-18", "cst-simplification-19",
            "cst-simplification-2", "cst-simplification-20",
            "cst-simplification-21", "cst-simplification-22",
            "cst-simplification-3", "cst-simplification-4",
            "cst-simplification-5", "cst-simplification-6",
            "cst-simplification-7", "cst-simplification-8",
            "cst-simplification-9",
        ),
    ),
    (
        "analysis",
        "Analysis and normalization",
        "heuristics",
        "Heuristics and identities",
        ("example-guessing", "get-ident-1", "get-ident-2", "get-ident-3"),
    ),
    (
        "arithmetic",
        "Arithmetic",
        "multiplication",
        "Multiplication",
        ("mul-factor-1", "mul-factor-2", "mul-mba-1", "mul-mba-2", "mul-mba-3", "mul-mba-4"),
    ),
    (
        "arithmetic",
        "Arithmetic",
        "negation",
        "Negation",
        (
            "neg-add-hackers-delight-1", "neg-add-hackers-delight-2",
            "neg-or-hackers-delight-1", "neg-sub-hackers-delight-1",
            "neg-xor-hackers-delight-1", "neg-xor-hackers-delight-2",
            "neg-hackers-delight-1", "neg-hackers-delight-2",
        ),
    ),
    (
        "boolean",
        "Boolean algebra",
        "or",
        "OR",
        (
            "or-bnot-factor-1", "or-bnot-factor-2", "or-bnot-factor-3",
            "or-bnot-factor-4", "or-chain", "or-factor-1", "or-factor-2",
            "or-factor-3", "or-hackers-delight-1", "or-hackers-delight-2",
            "or-hackers-delight-2-variant-1", "or-hodur-1", "or-hodur-2",
            "or-mba-1", "or-mba-1-commuted", "or-mba-2", "or-mba-3",
            "or-ollvm-1", "or-1", "or-2", "or-3", "or-4",
        ),
    ),
    (
        "predicates",
        "Predicates",
        "predicate-simplification",
        "Predicate simplification",
        (
            "pred-0-1", "pred-0-2", "pred-0-3", "pred-0-4", "pred-0-5",
            "pred-0-6", "pred-0-7", "pred-ff-1", "pred-ff-2", "pred-ff-3",
            "pred-ff-4", "pred-odd-1", "pred-odd-2", "pred-or-1-1",
            "pred-or-2-1", "pred-setb-1", "pred-setnz-1", "pred-setnz-2",
            "pred-setnz-3", "pred-setnz-4", "pred-setnz-5", "pred-setnz-6",
            "pred-setnz-8", "pred-setz-1", "pred-setz-2", "pred-setz-3",
        ),
    ),
    (
        "analysis",
        "Analysis and normalization",
        "normalization",
        "Normalization helpers",
        (
            "replace-mov-high-context", "replace-readonly-address-of-with-immediate",
            "rotate-helper-inline", "set-global-variables-to-zero-if-detected-read-only",
        ),
    ),
    (
        "arithmetic",
        "Arithmetic",
        "subtraction",
        "Subtraction",
        (
            "sub-1-add-hackers-delight-1", "sub-1-and-1-mba-1",
            "sub-1-and-hackers-delight-1", "sub-1-or-mba-1", "sub-1-factor-1",
            "sub-1-factor-2", "sub-hackers-delight-1", "sub-hackers-delight-2",
            "sub-hackers-delight-3", "sub-hackers-delight-4",
        ),
    ),
    (
        "protection-specific",
        "Protection-specific rewrites",
        "tigress",
        "Tigress",
        (
            "tigress-add-via-xor-or", "tigress-increment",
            "tigress-multiply-bit-partition", "tigress-not-equal-sign-bit",
            "tigress-not-equal-sign-bit-64", "tigress-xor-via-or-minus-and",
            "tigress-xor-via-sub-or",
        ),
    ),
    (
        "arithmetic",
        "Arithmetic",
        "unsigned",
        "Unsigned arithmetic",
        ("unsigned-magic-modulo-3",),
    ),
    (
        "analysis",
        "Analysis and normalization",
        "specialized",
        "Specialized rewrites",
        ("weird-1", "weird-2", "weird-3", "weird-4", "weird-5", "weird-6"),
    ),
    (
        "boolean",
        "Boolean algebra",
        "xor",
        "XOR",
        (
            "xor-1-mba-1", "xor-almost-1", "xor-chain", "xor-factor-1",
            "xor-factor-2", "xor-factor-3", "xor-hackers-delight-1",
            "xor-hackers-delight-2", "xor-hackers-delight-3",
            "xor-hackers-delight-4", "xor-hackers-delight-5", "xor-hodur-1",
            "xor-hodur-2", "xor-mba-1", "xor-mba-2", "xor-mba-3",
            "xor-nested-stuff", "xor-1", "xor-2", "xor-3", "xor-4",
            "xor-4-with-xdu", "xor-special-constant-1", "xor-special-constant-2",
        ),
    ),
    (
        "solver",
        "Solver-assisted rewrites",
        "z3",
        "Z3",
        (
            "z-3-constant-optimization", "z-3-smod-generic", "z-3-lnot-generic",
            "z-3-setnz-generic", "z-3-setz-generic",
        ),
    ),
)

_SPECIAL_TRANSFORM_METADATA = {
    "mul-mba-1": {
        "description": "Simplify an MBA multiplication pattern to x * y.",
        "reference": "MBA obfuscation with double bnot verification",
        "verification": VerificationStatus.SKIPPED,
        "verification_reason": "Offline SMT proof exceeds the practical verification budget.",
        "advisory": AdvisoryTone.WARNING,
        "advisory_reason": "SMT verification is skipped because the offline proof is expensive.",
        "cost": TransformCost.PROOF_EXPENSIVE,
        "cost_detail": "Four multiplications make the offline SMT proof impractical.",
    },
    "mul-mba-2": {
        "description": "Known-incorrect MBA multiplication rewrite with a constant.",
        "reference": "Multiplication does not distribute over these bitwise operations.",
        "default_selected": False,
        "verification": VerificationStatus.KNOWN_INCORRECT,
        "verification_reason": "The rule is documented as mathematically incorrect.",
        "advisory": AdvisoryTone.DANGER,
        "advisory_reason": "Known incorrect: enable only when you deliberately accept this rewrite.",
    },
    "mul-mba-3": {
        "description": "Known-incorrect MBA multiplication rewrite with an even constant.",
        "reference": "Multiplication does not distribute over these bitwise operations.",
        "default_selected": False,
        "verification": VerificationStatus.KNOWN_INCORRECT,
        "verification_reason": "The rule is documented as mathematically incorrect.",
        "advisory": AdvisoryTone.DANGER,
        "advisory_reason": "Known incorrect: enable only when you deliberately accept this rewrite.",
    },
    "mul-mba-4": {
        "description": "Simplify an MBA NOT/OR multiplication pattern to x * y.",
        "reference": "MBA obfuscation with bnot verification",
        "verification": VerificationStatus.SKIPPED,
        "verification_reason": "Offline SMT proof exceeds the practical verification budget.",
        "advisory": AdvisoryTone.WARNING,
        "advisory_reason": "SMT verification is skipped because the offline proof is expensive.",
        "cost": TransformCost.PROOF_EXPENSIVE,
        "cost_detail": "Three multiplications make the offline SMT proof impractical.",
    },
}


def _label(transform_id: str) -> str:
    return transform_id.replace("-", " ").upper()


def _build_specs() -> tuple[TransformEditorSpec, ...]:
    specs: list[TransformEditorSpec] = []
    seen: set[str] = set()
    for family_id, family_label, subfamily_id, subfamily_label, transform_ids in _FAMILY_MEMBERSHIP:
        for transform_id in transform_ids:
            if transform_id in seen:
                raise ValueError(f"duplicate checked-in MBA catalog transform {transform_id!r}")
            seen.add(transform_id)
            details = _SPECIAL_TRANSFORM_METADATA.get(transform_id, {})
            specs.append(
                TransformEditorSpec(
                    transform_id=transform_id,
                    label=str(details.get("label", _label(transform_id))),
                    family_id=family_id,
                    family_label=family_label,
                    subfamily_id=subfamily_id,
                    subfamily_label=subfamily_label,
                    description=str(details.get("description", "Registered MBA simplification transform.")),
                    reference=str(details.get("reference", "D810 MBA transform catalog.")),
                    maturities=("any",),
                    # A new mba-simplify pass starts conservatively. Existing
                    # projects retain their explicit selection, while an
                    # operator can select a family/subfamily intentionally.
                    default_selected=bool(details.get("default_selected", False)),
                    verification=details.get("verification", VerificationStatus.UNAVAILABLE),
                    verification_reason=str(details.get("verification_reason", "No config-v2 verification classification is recorded.")),
                    advisory=details.get("advisory", AdvisoryTone.NONE),
                    advisory_reason=str(details.get("advisory_reason", "")),
                    cost=details.get("cost", TransformCost.UNKNOWN),
                    cost_detail=str(details.get("cost_detail", "")),
                    option_fields=MBA_TRANSFORM_OPTION_FIELDS.get(transform_id, ()),
                )
            )
    registered_ids = tuple(stage.stage_id for stage in mba_transform_stages())
    catalog_ids = tuple(item.transform_id for item in specs)
    if catalog_ids != registered_ids:
        raise ValueError(
            "checked-in MBA transform catalog must exactly match registered transform IDs"
        )
    return tuple(specs)


MBA_TRANSFORM_SPECS = _build_specs()


def mba_transform_editor_spec() -> PassEditorSpec:
    """Return the fixed transform-catalog editor for ``mba-simplify``."""
    return PassEditorSpec.transform_catalog(MBA_TRANSFORM_SPECS)


__all__ = ["MBA_TRANSFORM_SPECS", "mba_transform_editor_spec"]
