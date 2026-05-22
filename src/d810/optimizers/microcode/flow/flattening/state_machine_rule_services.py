"""Generic rule-host proxy for state-machine family adapters."""
from __future__ import annotations

__all__ = ["RuleHostProxy", "StateMachineRuleServices"]


class RuleHostProxy:
    """Proxy service state reads/writes to a concrete optimizer rule instance."""

    def __init__(self, rule) -> None:
        object.__setattr__(self, "_rule", rule)

    def __getattr__(self, name: str):
        return getattr(self._rule, name)

    def __setattr__(self, name: str, value) -> None:
        if name == "_rule" or hasattr(type(self), name):
            object.__setattr__(self, name, value)
            return
        setattr(self._rule, name, value)


class StateMachineRuleServices(RuleHostProxy):
    """Base proxy surface for state-machine family rule services."""
