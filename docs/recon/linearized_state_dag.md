# LinearizedStateDag Contract

`LinearizedStateDag` is the recon-layer authority for Hodur state-machine
topology. It describes two different graphs:

- The outer semantic DAG: state-to-state transitions after dispatcher and BST
  analysis.
- The node-local CFG: the block/segment structure that belongs to one semantic
  state node.

Planner code should consume these typed facts directly through
`AnalysisSnapshot.discovery`, `ReconRoundDiscoveryContext.local_facts`,
`DagAuthority`, or the DAG object itself. Rendered program text is for humans
and tests of the renderer only. Do not scrape rendered text to recover planner
facts.

## Layer Ownership

- `d810.recon` builds and owns facts. It discovers state identity, local block
  ownership, shared suffixes, and semantic edges.
- `d810.cfg` owns intent primitives and graph modifications. It can reference
  recon facts through lower-layer key types such as `StateDagNodeKey`, but it
  must not import recon builders.
- `d810.hexrays` owns backend capability and physical microcode mutation.
- HCC and other optimizer strategies orchestrate. They decide which recon facts
  to lower into cfg intents, then let backend code apply those intents.

## StateDagNode

One `StateDagNode` is one semantic state family. Important fields:

- `key`: stable identity. `key.state_const` is the exact state value when known.
  `key.range_lo` and `key.range_hi` identify range-backed states. The key lives
  in `d810.cfg.state_dag_key` so cfg-layer code can carry identities without a
  cfg-to-recon import.
- `kind`: `EXACT` or `RANGE_BACKED`.
- `state_label`: human-readable label such as `STATE_298372CC`.
- `handler_serial`: the handler block that represents this state family.
- `entry_anchor`: the concrete entry block for this node. Lowering code should
  prefer this over parsing labels.
- `owned_blocks`: all local blocks that belong to the state node, including
  shared suffix blocks when the node reaches them.
- `exclusive_blocks`: blocks owned only by this node before shared suffix
  convergence.
- `shared_suffix_blocks`: suffix blocks reached by more than one state-local
  path.
- `local_segments`: typed segment groups for node-local rendering and analysis.
- `local_edges`: typed local CFG edges between those segments.

`owned_blocks`, `exclusive_blocks`, and `shared_suffix_blocks` answer different
questions. Do not substitute one for another:

- Use `owned_blocks` when asking "which blocks are in this state-local body?"
- Use `exclusive_blocks` when asking "which blocks can be safely cloned or
  moved without affecting another state family?"
- Use `shared_suffix_blocks` when asking "where does this local body converge
  with other local paths?"

## StateLocalSegment

`StateLocalSegment` groups one or more microcode blocks inside a state node.

- `segment_id`: stable local label, usually `blk[N]`.
- `kind`: segment role, for example `STRAIGHT_LINE`, `BRANCH`, `GOTO_LABEL`,
  `JOIN`, `SHARED_SUFFIX`, or `TERMINAL_SUFFIX`.
- `blocks`: block serials carried by the segment, in local order.

Segments are local to a node. `blk[205]` in one node's segment graph is not an
outer DAG node; it is a local CFG anchor inside that state family.

## StateLocalEdge

`StateLocalEdge` describes node-local control flow between segments.

- `source_segment_id`: source segment such as `blk[205]`.
- `target_segment_id`: target segment such as `blk[207]`.
- `kind`: edge role. Current important values are `FALLTHROUGH`, `TAKEN`,
  `GOTO`, `JOIN`, `SHARED_SUFFIX`, and `TERMINAL`.
- `branch_arm`: optional physical branch arm when the edge came from a
  conditional source.

Example local CFG:

```text
STATE_298372CC:
    // entry blk[205] [range_backed]
    // blocks: blk[205], blk[207], blk[206], blk[217], blk[218]
    // shared-suffix: blk[217], blk[218]
    // local-cfg: blk[205] -taken-> blk[207], blk[205] -fallthrough-> blk[206], blk[206] -shared_suffix-> blk[217], blk[217] -terminal-> blk[218]
```

That text is a rendering of typed facts:

- `blocks` comes from `StateDagNode.owned_blocks`.
- `shared-suffix` comes from `StateDagNode.shared_suffix_blocks`.
- `local-cfg` comes from `StateDagNode.local_edges`.

## StateDagEdge

`StateDagEdge` is an outer semantic DAG edge. It does not describe local CFG
inside one state.

- `kind`: `TRANSITION`, `CONDITIONAL_TRANSITION`, `CONDITIONAL_RETURN`,
  `EXIT_ROUTINE`, or `UNKNOWN`.
- `source_key`: source state node identity.
- `target_key`: target state node identity when the target is another state.
- `target_state`: target state constant when known.
- `target_entry_anchor`: concrete entry block for the target state.
- `source_anchor`: redirectable source anchor. It carries `block_serial` and
  optional `branch_arm`.
- `ordered_path`: physical block path used to justify the semantic edge.
- `last_write_site`: optional `(block_serial, insn_index)` of the state write.

Use outer DAG edges for state-to-state reachability and lowering decisions.
Use local edges for the shape inside a state body.

## Runtime Access

`ReconRoundDiscoveryContext.local_facts` exposes common lookups:

- `node_by_entry[entry_block] -> StateDagNode`
- `node_by_handler[handler_serial] -> StateDagNode`
- `node_by_owned_block[block_serial] -> StateDagNode`
- `node_by_any_local_block[block_serial] -> StateDagNode`
- `owned_blocks_by_entry[entry_block] -> frozenset[int]`
- `shared_suffix_by_entry[entry_block] -> frozenset[int]`
- `local_edges_by_entry[entry_block] -> tuple[StateLocalEdge, ...]`

These are in-memory planner facts. Runtime strategies must not query the diag
database to make lowering decisions.

## Diagnostic Database Mirror

The diag database stores both the outer semantic DAG and node-local facts.

All DAG-local tables use the same diagnostic node identity for `state_hex`:
`state_const` when present, otherwise `range_lo` for range-backed nodes,
otherwise a stable synthetic handler/range identity. This identity is a storage
key, not necessarily a semantic state constant.

Outer DAG tables:

- `dag_nodes`: state, entry block, classification, and shared suffix summary.
- `dag_edges`: semantic state-to-state or state-to-return edges.

Node-local fact tables:

- `dag_node_blocks`: one row per `(state, entry, role, block)` with role
  `owned`, `exclusive`, or `shared_suffix`.
- `dag_local_segments`: one row per local segment with segment kind and blocks.
- `dag_local_edges`: one row per local edge with source segment, target segment,
  edge kind, and branch arm.

Human rendering should be done on demand from these tables:

```bash
PYTHONPATH=src python -m d810.core.diag state-local --db "$DB" --snapshot 6 0x298372CC
```

The DB renderer is diagnostic only. It exists so investigations can answer
"what did recon know?" without grepping logs or relying on a pre-rendered text
variant.

## HCC Fusion Example

For a semantic chain like:

```text
37B42A40 -> 63D54755 -> 57BE6FD0
```

HCC should reason from typed DAG facts:

1. Find the `StateDagEdge` whose `target_key` is the region head.
2. Use `source_anchor.block_serial`, `target_entry_anchor`, and `ordered_path`
   to identify the semantic incoming edge.
3. Use `local_facts` to determine whether the source block is part of another
   state's local body.
4. If the source is already covered by an upstream composable region, treat the
   problem as region fusion, not as an independent splice.

The critical distinction is that a block can be a valid physical predecessor
for one composed region while also being a state-local block owned by another
semantic state. The DAG and `local_facts` expose that distinction explicitly;
rendered labels do not.

## Rules

- Planner logic consumes typed DAG/context facts, never rendered text.
- Use outer `StateDagEdge` facts for semantic reachability.
- Use `StateLocalEdge` facts for intra-state branch and suffix structure.
- Preserve layer boundaries: recon facts do not emit cfg modifications directly.
- If a needed fact is only available in rendered text, the DAG contract is
  missing a typed field. Add the typed field instead of scraping.
