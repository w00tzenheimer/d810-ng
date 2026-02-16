"""Flow optimizer package.

Import rule modules here so their FlowOptimizationRule subclasses register
eagerly via Registrant metaclass side effects.
"""

try:
    import ida_hexrays  # noqa: F401
except ImportError:
    # Allow package import in non-IDA environments.
    pass
else:
    # Registration side-effects for commonly used flow rules.
    from d810.optimizers.microcode.flow.constant_prop import global_const_inline  # noqa: F401
    from d810.optimizers.microcode.flow.flattening import block_merge  # noqa: F401
    from d810.optimizers.microcode.flow.flattening import mba_state_preconditioner  # noqa: F401
    from d810.optimizers.microcode.flow.jumps import indirect_branch  # noqa: F401
    from d810.optimizers.microcode.flow.jumps import indirect_call  # noqa: F401
    from d810.optimizers.microcode.flow import identity_call  # noqa: F401
