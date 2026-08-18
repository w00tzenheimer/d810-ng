"""Attested no-op script used to journal manager-owned type proposals.

The preparation gateway always executes a source-attested script step. Type
proposals themselves are applied by the gateway before this file executes, so
the file intentionally performs no IDB operation.
"""
