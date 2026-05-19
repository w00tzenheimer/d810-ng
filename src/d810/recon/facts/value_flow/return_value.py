"""Return-value fact.

A recovered semantic value at the function return boundary. This is distinct
from a return slot/storage observation: the slot is the carrier, while this
fact names the value that is being returned through it.
"""
from __future__ import annotations

RETURN_VALUE_FACT_TYPE = "ReturnValueFact"

__all__ = ["RETURN_VALUE_FACT_TYPE"]
