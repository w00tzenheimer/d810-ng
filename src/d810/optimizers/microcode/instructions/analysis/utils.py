from d810.hexrays.expr.ast import AstLeaf, AstNode


def get_possible_patterns(
    ast, min_nb_use=2, ref_ast_info_by_index=None, max_nb_pattern=64
):
    # max_nb_pattern is used to prevent memory explosion when very large patterns are parsed
    if ast.is_leaf():
        return [ast]
    if ref_ast_info_by_index is None:
        # A root entry can survive while descendant entries are stale after
        # Hex-Rays or an optimizer mutates the AST.  This call owns the index
        # when no explicit reference mapping was supplied, so rebuild the
        # complete subtree unconditionally before recursive lookup.
        ast.compute_sub_ast()
        ref_ast_info_by_index = ast.sub_ast_info_by_index
    possible_patterns = []
    ast_info = ref_ast_info_by_index.get(ast.ast_index)
    # A missing descendant has no authoritative multiplicity witness.  It may
    # still contribute its concrete recursive patterns, but must not be
    # abstracted into a repeated-variable leaf (and must never abort the
    # optimizer hook with a KeyError).
    if ast_info is not None and ast_info.number_of_use >= min_nb_use:
        node_as_leaf = AstLeaf("x_{0}".format(ast.ast_index))
        node_as_leaf.mop = ast.mop
        node_as_leaf.ast_index = ast.ast_index
        possible_patterns.append(node_as_leaf)
    left_patterns = []
    right_patterns = []
    if ast.left is not None:
        left_patterns = get_possible_patterns(
            ast.left, min_nb_use, ref_ast_info_by_index, max_nb_pattern
        )
    if ast.right is not None:
        right_patterns = get_possible_patterns(
            ast.right, min_nb_use, ref_ast_info_by_index, max_nb_pattern
        )

    for left_pattern in left_patterns:
        if ast.right is not None:
            for right_pattern in right_patterns:
                node = AstNode(ast.opcode, left_pattern, right_pattern)
                node.mop = ast.mop
                node.ast_index = ast.ast_index
                if len(possible_patterns) < max_nb_pattern:
                    possible_patterns.append(node)
        else:
            node = AstNode(ast.opcode, left_pattern)
            node.mop = ast.mop
            node.ast_index = ast.ast_index
            if len(possible_patterns) < max_nb_pattern:
                possible_patterns.append(node)
    return possible_patterns
