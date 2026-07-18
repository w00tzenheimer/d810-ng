"""Compatibility re-exports for the production native closure planner."""

from d810.analyses.control_flow.native_semantic_closure import (
    ClosureAbstention,
    ClosureAbstentionReason,
    NativeBlock,
    NativeCfg,
    NativeEdge,
    NativeEdgeKind,
    NativeRange,
    NativeSemanticClosure,
    NativeTerminalKind,
    ProvenImportBoundaryEdge,
    ProvenInternalEdge,
    ResolverProvenDependencyDefinition,
    ResolverProvenHandlerEntry,
    plan_native_semantic_closure,
)

__all__ = [
    "ClosureAbstention",
    "ClosureAbstentionReason",
    "NativeBlock",
    "NativeCfg",
    "NativeEdge",
    "NativeEdgeKind",
    "NativeRange",
    "NativeSemanticClosure",
    "NativeTerminalKind",
    "ProvenImportBoundaryEdge",
    "ProvenInternalEdge",
    "ResolverProvenDependencyDefinition",
    "ResolverProvenHandlerEntry",
    "plan_native_semantic_closure",
]
