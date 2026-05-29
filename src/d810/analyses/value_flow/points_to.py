"""Points-to fact.

An observed relationship between a carrier expression and the memory region it
addresses. This is the alias-analysis vocabulary for evidence such as Hodur
terminal byte emitters that already identify a destination buffer expression.
"""
from __future__ import annotations

POINTS_TO_FACT_TYPE = "PointsToFact"

__all__ = ["POINTS_TO_FACT_TYPE"]
