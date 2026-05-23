# Per-Function Rule Overrides

D-810 ng supports **per-function rule overrides**: any rule can be enabled or
disabled for a single function without touching project JSON or restarting the
plugin. Overrides persist to the project database, survive IDA restarts, and
are shared with teammates who open the same project.

## When to use it

The common case: a rule fires on a function and produces worse pseudocode than
the baseline. Instead of editing your project JSON and reloading the plugin,
right-click in the pseudocode view and disable just that rule for just that
function. The next decompile uses the new override.

Typical situations:

- An MBA rule rewrites an expression that was already readable.
- An unflattener mis-identifies a switch as flattening and damages control flow.
- A peephole rule trips an IDA edge case and produces a `void` return.
- You want to A/B compare "all rules on" vs "rule X off" on the same function.

## How to use it

1. Decompile the function (`F5`).
2. Right-click anywhere in the pseudocode view.
3. Open the **d810-ng** submenu.
4. Click **Function rules...**.

A dialog appears showing every rule D-810 ng knows about, grouped by category,
with a checkbox per rule. The header reads `Enabled for this function: N/M`.

To override:

- Untick a rule to disable it for the current function only.
- Tick a rule that was disabled by default to force-enable it for this function.
- **Enable All** resets the function back to the project defaults.
- **Function Tags** lets you label this function (e.g. `dispatcher`,
  `mba-heavy`) for later filtering and analysis.
- **Notes** is a free-form text field that persists with the override; useful
  for explaining why a rule is disabled.

Click **Save**. The pseudocode view refreshes automatically with the new
override applied.

## Precedence

When D-810 ng decides whether a rule fires on a given function, it consults
sources in this order (highest priority first):

| Priority | Source | Where it lives |
|-|-|-|
| 1 | Per-function override (this dialog) | Project database, persisted |
| 2 | Whitelist / blacklist for this function | Project JSON, persisted |
| 3 | Runtime suppression from recon analysis | In-memory, per decompile |
| 4 | Global rule activation | Project JSON `ins_rules` / `blk_rules` |

So a per-function override always wins. If you disable a rule here and the
global config has it enabled, the rule still does not fire on this function.

## Where overrides are stored

Overrides live in the project database (per-IDB). To inspect or edit by hand:

```bash
python3 tools/d810cli.py paths       # locate the database
python3 tools/d810cli.py stats       # see active overrides
```

Overrides export with the project JSON, so committing the project file to your
team's repo shares them automatically.

## Programmatic access

The same store backs the `Manager.set_function_rule_override` API
(`src/d810/manager.py`). Tests and analysis scripts can set overrides without
going through the dialog. See
`tests/system/e2e/test_emulated_dispatcher_parity.py` for an example.

```python
manager.set_function_rule_override(
    function_addr=0x1800134A5,
    enabled_rules={"EmulatedDispatcherUnflattener"},
    disabled_rules={"HodurUnflattener"},
    notes="OLLVM region, not Hodur",
)
```

The call invalidates the rule-scope cache for that function and re-decompiles
on the next view refresh.

## Removing an override

Open **Function rules...** again on the same function and click **Enable All**
followed by **Save**. The override is cleared and the function reverts to
project defaults.

To clear all overrides for a project, delete the project database file
(location from `tools/d810cli.py paths`) and reload the project.

## Related

- Right-click submenu lives under **d810-ng/** in pseudocode and disassembly
  views.
- The action ID is `d810ng:function_rules` if you want to bind a hotkey via
  IDA's keyboard shortcuts.
- Project-wide rule activation is controlled by the project JSON loaded via
  `Ctrl-Shift-D`.
