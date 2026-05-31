#!/usr/bin/env python3
"""Generate a per-phase MOVE executor Workflow script from .tmp/thinning/phase_<P>.json.

Each generated executor relocates one phase's files into their LLVM/LiSA taxonomy home,
serially, one gate-verified commit per slice, halt-on-red. Per-slice gate is FAST
(lint-imports + sg + check-cycles + import-smoke); the full unit suite runs ONCE at phase end
(a single trailing agent). Golden (F/G) is run separately, in-session, after the phase commits.

Usage:  pyenv exec python tools/scripts/thinning_gen_executor.py D
        -> writes .tmp/thinning/executor_phase_D.js
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

WT = "/Users/mahmoud/src/idapro/d810/.worktrees/llvm-lisa-restructure"


def gen(phase: str) -> Path:
    slices = json.loads(Path(f".tmp/thinning/phase_{phase}.json").read_text())
    slices_js = json.dumps(slices, indent=2)
    js = f"""export const meta = {{
  name: 'thinning-executor-phase{phase}',
  description: 'Phase {phase}: relocate {len(slices)} files into taxonomy homes, serial, fast-gate per slice, unit suite at phase end, halt-on-red',
  phases: [{{ title: 'Move', detail: '{len(slices)} relocations, serial' }}, {{ title: 'PhaseGate', detail: 'full unit suite once' }}],
}}

const WT = '{WT}'
const PHASE = '{phase}'
const SLICES = {slices_js}

const RESULT_SCHEMA = {{
  type: 'object',
  properties: {{
    status: {{ type: 'string', enum: ['green', 'red', 'skip'] }},
    commit: {{ type: 'string' }},
    new_module: {{ type: 'string' }},
    failed_check: {{ type: 'string' }},
    detail: {{ type: 'string' }},
  }},
  required: ['status', 'detail'],
}}

function movePrompt(s) {{
  const oldmod = 'd810.' + s.path.replace(/\\.py$/, '').replace(/\\//g, '.')
  return [
    `BYTE-IDENTICAL thinning Phase ${{PHASE}} (${{s.role}} relocation). Worktree: ${{WT}}. ALWAYS cd ${{WT}} first.`,
    `Move file: src/d810/${{s.path}}   (old module: ${{oldmod}})`,
    `Classifier destination hint: "${{s.dest}}"${{s.seam ? '  [needs_seam: IDA-touching; relocate AS-IS to the evidence home, do NOT attempt a portable split]' : ''}}`,
    ``,
    `Compute the NEW location:`,
    `- Let DEST = "${{s.dest}}"; if it does not start with "d810.", prepend "d810.".`,
    `- stem = basename without .py. If DEST's last segment == stem, DEST already names the file module:`,
    `    new_module = DEST ; new_path = src/d810/ + DEST.slice(5).replaceAll('.', '/') + '.py'`,
    `  else DEST is a PACKAGE: new_module = DEST + '.' + stem ; new_path = src/d810/<DEST as dir>/<basename>`,
    `Steps:`,
    `1. Read src/d810/${{s.path}} to confirm it exists and note its imports.`,
    `2. Ensure every destination package dir exists with an __init__.py (create + git add missing __init__.py only).`,
    `3. cd ${{WT}} && git mv src/d810/${{s.path}} <new_path>`,
    `4. Repoint EVERY importer of ${{oldmod}} to new_module across src tests tools:`,
    `   git grep -nE "${{oldmod.replace(/\\./g, '\\\\\\\\.')}}([^A-Za-z0-9_]|$)" -- src tests tools`,
    `   cover 'from ${{oldmod}} import ...', 'import ${{oldmod}}( as)?', and dotted attribute use; preserve symbol names byte-for-byte.`,
    `   Fix the moved file's own intra-package relative/absolute self-imports if needed.`,
    `5. FAST GATE (run from ${{WT}}, ALL must pass):`,
    `   PYTHONPATH=src lint-imports --config .importlinter           # "13 kept, 0 broken"`,
    `   sg scan --config sgconfig.yml --report-style short           # clean`,
    `   pyenv exec python tools/scripts/check-cycles.py              # "no import cycles"`,
    `   PYTHONPATH=src pyenv exec python -c "import d810; import <new_module>"   # import-smoke resolves`,
    `6. green: cd ${{WT}} && git add -A && git commit -m "refactor(thinning): relocate ${{s.path}} -> <new_module>"`,
    `   return {{status:"green", commit:<short hash>, new_module:<new_module>, detail:"ok"}}.`,
    `   red: cd ${{WT}} && git reset --hard HEAD && git clean -fd -- src ; return {{status:"red", failed_check:<which>, detail:<short>}}.`,
    `HARD SAFETY: touch ONLY ${{s.path}}, its importers, and created __init__.py files. Never edit unrelated logic.`,
    `If the destination is ambiguous or a name collision exists, return {{status:"red", detail:"ambiguous: <why>"}} with NO changes (after git reset --hard).`,
  ].join('\\n')
}}

phase('Move')
const ledger = []
let halted = false
for (const s of SLICES) {{
  const r = await agent(movePrompt(s), {{ label: `${{PHASE}}:` + s.path.split('/').pop(), phase: 'Move', schema: RESULT_SCHEMA, agentType: 'implementer' }})
  const st = r ? r.status : 'red'
  ledger.push({{ slice: s.path, status: st, commit: r && r.commit, new_module: r && r.new_module, detail: r ? r.detail : 'no result' }})
  log(`${{s.path}}: ${{st}} ${{r && r.commit ? r.commit : ''}} -> ${{r && r.new_module ? r.new_module : ''}} | ${{r ? r.detail : 'no result'}}`)
  if (st === 'red') {{ halted = true; log(`HALT at ${{s.path}}`); break }}
}}

let phaseGate = 'skipped'
if (!halted) {{
  phase('PhaseGate')
  const g = await agent(
    `cd ${{WT}} && run the full unit suite: PYTHONPATH=src:tests pyenv exec python -m pytest tests/unit/ -q . ` +
    `Return {{status:"green"}} if it shows no NEW failures vs baseline (3742 passed, 23 skipped), else {{status:"red", detail:<failing tests>}}.`,
    {{ label: `${{PHASE}}:phase-unit-gate`, phase: 'PhaseGate', schema: {{ type: 'object', properties: {{ status: {{ type: 'string' }}, detail: {{ type: 'string' }} }}, required: ['status'] }} }}
  )
  phaseGate = g ? g.status : 'red'
}}

const green = ledger.filter((x) => x.status === 'green').length
const skipped = ledger.filter((x) => x.status === 'skip').length
return {{ phase: PHASE, total: SLICES.length, green, skipped, halted, phaseGate, ledger }}
"""
    out = Path(f".tmp/thinning/executor_phase_{phase}.js")
    out.write_text(js)
    print(f"wrote {out}  ({len(slices)} slices)")
    return out


if __name__ == "__main__":
    for ph in sys.argv[1:]:
        gen(ph)
