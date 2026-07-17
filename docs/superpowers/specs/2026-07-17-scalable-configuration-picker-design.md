# Scalable Configuration Picker Design

## Goal

Replace the flat configuration combobox in the D-810 Configuration form with a searchable picker that remains truthful about the full project inventory. Every discovered JSON project, including config-v2 canary runtime documents, remains directly selectable.

## User experience

The Project header shows the active project filename with a dropdown affordance in a compact button. Clicking it opens an anchored searchable popup directly beneath that control.

The picker contains:

- A focused filter field with the placeholder `Search configurations by filename, description, or runtime...`.
- A compact two-column list: filename first, routing behavior second, and full descriptions in tooltips.
- A visible result count plus single-click or Enter selection; the popup closes before the existing configuration-loading path runs.

Each result represents exactly one discovered `ProjectConfiguration`. Filtering never removes projects from the underlying catalog and never changes the project index carried by a result. The selected row loads the existing `ProjectManager` index through `D810State.load_project`.

## Routing presentation

The picker labels supported config-v2 pairs using the existing default-routing mappings:

- A selectable source config whose mapped runtime is present says `Config v2 -> <runtime filename>`.
- A selectable mapped runtime says `Config v2 runtime (direct)`.
- Every other config says `Direct project`.

The existing Project identity rows remain the post-selection authority for mode, source, runtime, and effective passes. The picker provides browse-time context; it does not reimplement runtime activation.

## Architecture

`d810.ui.project_picker_logic` is a Qt-free projection layer. It produces immutable picker entries with their original manager index, filename, behavior text, description, and normalized search text. It also filters entries without changing those stable identities.

`d810.ui.project_picker_popup` is a thin IDA/Qt popup. It renders entries from the pure layer, retains their original manager indices while filtering, and calls back with that index only after selection. `D810ConfigForm_t` owns popup creation and retains existing `_load_config(index)` as the sole configuration activation path.

## Constraints

- Do not hide, exclude, or collapse any discovered JSON project.
- Do not mutate selection while the user filters or cancels the picker.
- Do not change discovery, persistence, source/runtime activation, deletion policy, or config-v2 editing behavior.
- Preserve headless imports: the pure logic module imports no Qt or IDA modules; the popup has an import-safe non-IDA stub.
- Test stable-index selection, routing labels, filtering, and the form-to-popup contract before native validation.

## Validation

Run focused unit and UI-contract tests, the full unit suite, ast-grep, import-linter, and `graphify update .`. Launch the named X11 IDA image against a copied sample database and inspect the picker with a large user configuration inventory.
