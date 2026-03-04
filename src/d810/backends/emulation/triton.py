"""Triton-based symbolic emulation backend."""

from __future__ import annotations

from d810.backends.emulation.common import Architecture, logger

try:
    from triton import ARCH as TRITON_ARCH
    from triton import AST_REPRESENTATION
    from triton import TritonContext

    TRITON_AVAILABLE = True
except ImportError:
    TRITON_AVAILABLE = False
    TritonContext = None


class TritonEmulator:
    """Symbolic execution backend implemented with Triton."""

    def __init__(self, arch: Architecture = Architecture.X86_64):
        self.arch = arch
        self._triton: TritonContext | None = None
        self._init_triton()

    @property
    def available(self) -> bool:
        return self._triton is not None

    def reset(self) -> None:
        if self._triton:
            self._triton.reset()

    def prove_branch(
        self,
        condition_ast,
        constraints: list | None = None,
    ) -> tuple[bool | None, dict]:
        if not self.available:
            return (None, {})
        assert self._triton is not None

        try:
            if constraints:
                for c in constraints:
                    self._triton.pushPathConstraint(c)

            neg_cond = self._triton.getAstContext().lnot(condition_ast)
            if not self._triton.isSat(neg_cond):
                return (True, {})
            if not self._triton.isSat(condition_ast):
                return (False, {})
            return (None, {})
        except Exception as e:
            logger.debug("Triton prove error: %s", e)
            return (None, {})

    def enumerate_values(
        self,
        expr_ast,
        max_values: int = 8,
    ) -> list[int] | None:
        if not self.available:
            return None
        assert self._triton is not None

        try:
            values: list[int] = []
            ast_ctx = self._triton.getAstContext()

            for _ in range(max_values):
                if self._triton.isSat(ast_ctx.equal(expr_ast, expr_ast)):
                    model = self._triton.getModel(ast_ctx.equal(expr_ast, expr_ast))
                    if not model:
                        break

                    value = expr_ast.evaluate()
                    if value is not None and value not in values:
                        values.append(value)
                        self._triton.pushPathConstraint(
                            ast_ctx.lnot(
                                ast_ctx.equal(
                                    expr_ast,
                                    ast_ctx.bv(value, expr_ast.getBitvectorSize()),
                                )
                            )
                        )
                    else:
                        break
                else:
                    break
            return values if values else None
        except Exception as e:
            logger.debug("Triton enumerate error: %s", e)
            return None

    def _init_triton(self) -> None:
        if not TRITON_AVAILABLE:
            logger.debug("Triton not available")
            return

        try:
            self._triton = TritonContext()
            if self.arch == Architecture.X86_64:
                self._triton.setArchitecture(TRITON_ARCH.X86_64)
            elif self.arch == Architecture.X86:
                self._triton.setArchitecture(TRITON_ARCH.X86)
            elif self.arch == Architecture.ARM64:
                self._triton.setArchitecture(TRITON_ARCH.AARCH64)

            self._triton.setAstRepresentationMode(AST_REPRESENTATION.PYTHON)
            logger.debug("Triton initialized for %s", self.arch.value)
        except Exception as e:
            logger.warning("Failed to initialize Triton: %s", e)
            self._triton = None

