# Scalable Configuration Picker Design

## Goal

Replace the flat configuration combobox in the D-810 Configuration form with a searchable picker that remains truthful about the full project inventory. Every discovered JSON project, including config-v2 canary runtime documents, remains directly selectable.

## User experience

The Project header shows the active project filename in a compact button. Clicking it opens a modal picker titled `Choose D-810 configuration`.

The picker contains:

- A focused filter field with the placeholder `Filter filename, description, or runtime...`.
- A non-editable result table with `Configuration`, `Behavior`, and `Description` columns.
- A visible result count, `Load selected` action, Cancel action, and double-click-to-load behavior.

Each result represents exactly one discovered `ProjectConfiguration`. Filtering never removes projects from the underlying catalog and never changes the project index carried by a result. The selected row loads the existing `ProjectManager` index through `D810State.load_project`.

## Routing presentation

The picker labels supported config-v2 pairs using the existing default-routing mappings:

- A selectable source config whose mapped runtime is present says `Config v2 -> <runtime filename>`.
- A selectable mapped runtime says `Config v2 runtime (direct)`.
- Every other config says `Direct project`.

The existing Project identity rows remain the post-selection authority for mode, source, runtime, and effective passes. The picker provides browse-time context; it does not reimplement runtime activation.

## Architecture

`d810.ui.project_picker_logic` is a Qt-free projection layer. It produces immutable picker entries with their original manager index, filename, behavior text, description, and normalized search text. It also filters entries without changing those stable identities.

`d810.ui.project_picker_dialog` is a thin IDA/Qt dialog. It renders entries from the pure layer and returns an original project index only after an explicit load action or double-click. `D810ConfigForm_t` owns dialog creation and retains existing `_load_config(index)` as the sole configuration activation path.

## Constraints

- Do not hide, exclude, or collapse any discovered JSON project.
- Do not mutate selection while the user filters or cancels the picker.
- Do not change discovery, persistence, source/runtime activation, deletion policy, or config-v2 editing behavior.
- Preserve headless imports: the pure logic module imports no Qt or IDA modules; the dialog has an import-safe non-IDA stub.
- Test stable-index selection, routing labels, filtering, and the form-to-dialog contract before native validation.

## Validation

Run focused unit and UI-contract tests, the full unit suite, ast-grep, import-linter, and `graphify update .`. Launch the named X11 IDA image against a copied sample database and inspect the picker with a large user configuration inventory.
