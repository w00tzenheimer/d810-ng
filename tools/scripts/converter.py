import argparse
import sys
from pathlib import Path

import libcst as cst
import libcst.matchers as m


class RuleBaseConverter(cst.CSTTransformer):
    """Convert every class inheriting from ``PatternMatchingRule`` so that
    its ``PATTERN`` and ``REPLACEMENT_PATTERN`` attributes become
    read-only ``@property`` methods.

    The transformation is performed for *all* classes under the processed
    files; it is safe to run repeatedly (idempotent) and will skip classes
    that already expose these names as properties.
    """

    TARGET_BASE: str = "PatternMatchingRule"

    def leave_ClassDef(
        self, original_node: cst.ClassDef, updated_node: cst.ClassDef
    ) -> cst.CSTNode:
        # Process only classes that (directly) inherit from PatternMatchingRule.
        if not any(
            m.matches(base.value, m.Name(self.TARGET_BASE))
            for base in updated_node.bases
        ):
            return updated_node

        # Ensure the class exclusively lists PatternMatchingRule as its sole base.
        new_base = cst.Arg(value=cst.Name(self.TARGET_BASE))
        new_cls = updated_node.with_changes(bases=[new_base])

        # ------------------------------------------------------------------
        # 2)  Transform ``PATTERN = ...`` and ``REPLACEMENT_PATTERN = ...``
        #     assignments into @property methods returning the same AST
        #     expressions.
        # ------------------------------------------------------------------

        pattern_expr: cst.BaseExpression | None = None
        replacement_expr: cst.BaseExpression | None = None
        remaining_body: list[cst.CSTNode] = []

        for stmt in new_cls.body.body:
            if (
                isinstance(stmt, cst.SimpleStatementLine)
                and len(stmt.body) == 1
                and isinstance(stmt.body[0], cst.Assign)
            ):
                assign: cst.Assign = stmt.body[0]
                # Only single-target assignments are expected here.
                if len(assign.targets) == 1 and isinstance(
                    assign.targets[0].target, cst.Name
                ):
                    target_name = assign.targets[0].target.value
                    if target_name == "PATTERN":
                        pattern_expr = assign.value
                        continue  # remove assignment
                    if target_name == "REPLACEMENT_PATTERN":
                        replacement_expr = assign.value
                        continue  # remove assignment
            remaining_body.append(stmt)

        # Build new function definitions for collected expressions.
        new_members: list[cst.CSTNode] = []

        def _make_property(name: str, expr: cst.BaseExpression) -> cst.FunctionDef:
            return cst.FunctionDef(
                name=cst.Name(name),
                decorators=[cst.Decorator(decorator=cst.Name("property"))],
                params=cst.Parameters(params=[cst.Param(name=cst.Name("self"))]),
                returns=cst.Annotation(annotation=cst.Name("AstNode")),
                body=cst.IndentedBlock(
                    [cst.SimpleStatementLine([cst.Return(value=expr)])]
                ),
            )

        if pattern_expr is not None:
            # Only add if a property with that name doesn't already exist.
            if not any(
                isinstance(el, cst.FunctionDef) and el.name.value == "PATTERN"
                for el in remaining_body
            ):
                new_members.append(_make_property("PATTERN", pattern_expr))

        if replacement_expr is not None:
            if not any(
                isinstance(el, cst.FunctionDef)
                and el.name.value == "REPLACEMENT_PATTERN"
                for el in remaining_body
            ):
                new_members.append(
                    _make_property("REPLACEMENT_PATTERN", replacement_expr)
                )

        # Assemble the final body order: original (sans assignments) + new members.
        final_body = remaining_body + new_members

        # If nothing left (possible but unlikely), add a pass.
        if len(final_body) == 0:
            final_body.append(cst.SimpleStatementLine([cst.Pass()]))

        new_cls = new_cls.with_changes(body=new_cls.body.with_changes(body=final_body))

        return new_cls


def _process_file(path: Path, in_place: bool = False) -> None:
    """Parse *path* with LibCST, apply the transformer, and either write the
    transformed code back to disk (``in_place=True``) or print it to STDOUT.
    """
    source = path.read_text(encoding="utf-8")
    module = cst.parse_module(source)
    transformed = module.visit(RuleBaseConverter())

    if in_place:
        path.write_text(transformed.code, encoding="utf-8")
    else:
        sys.stdout.write(transformed.code)


def _iter_py_files(target: Path):
    """Yield all ``*.py`` files under *target* (recursively if *target* is a
    directory). If *target* is already a Python file, yield it directly.
    """
    if target.is_file() and target.suffix == ".py":
        yield target
    elif target.is_dir():
        for file_path in target.rglob("*.py"):
            # Skip virtual environments / hidden directories for safety.
            if any(part.startswith(".") for part in file_path.parts):
                continue
            yield file_path


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Rewrite Add_HackersDelightRule_1 so that it directly inherits from "
            "PatternMatchingRule. The script uses LibCST, ensuring the output is "
            "properly formatted and syntactically correct."
        )
    )
    parser.add_argument(
        "paths",
        nargs="+",
        type=Path,
        help="Python files or directories to process.",
    )
    parser.add_argument(
        "--in-place",
        action="store_true",
        help="Overwrite files with the transformed code instead of printing to STDOUT.",
    )

    args = parser.parse_args(argv)

    for path in args.paths:
        for py_file in _iter_py_files(path):
            _process_file(py_file, in_place=args.in_place)


if __name__ == "__main__":
    main()
