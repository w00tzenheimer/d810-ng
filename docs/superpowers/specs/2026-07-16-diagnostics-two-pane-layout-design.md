# Diagnostics Two-Pane Layout Design

## Goal

Give structured diagnostic records half of the Diagnostics Explorer and keep
database, snapshot, and cleaner controls together in a denser left-hand work
area.

## Approved layout

The dock uses one outer horizontal splitter with equal initial sizes:

- Left pane: database and snapshot tables remain visible side-by-side in the
  upper section; the cleaner occupies the lower section.
- Right pane: structured-record filtering, table, detail text, and navigation
  controls occupy the full height.

The left pane uses a vertical splitter so users can trade height between the
browser and cleaner. The database/snapshot browser remains a nested horizontal
splitter. Cleaner action and confirmation controls wrap into compact grids, and
plan/result text uses full left-pane width rather than two narrow columns.

## Boundaries

- This is a Qt layout-only change. Inventory, sorting, filtering, cleanup
  planning, execution, navigation, and confirmation semantics do not change.
- The existing manager facade and pure `workbench_diagnostics_logic.py` seam
  remain authoritative.
- Initial proportions are outer 1:1, browser 1:1, and left browser-to-cleaner
  3:2. Every splitter remains user-adjustable.

## Verification

- A source contract proves the nested splitter ownership and equal outer
  stretch.
- Existing diagnostics adapter/logic tests prove action behavior is unchanged.
- A live Docker/XQuartz reload must show the right pane at approximately half
  the dock and the cleaner entirely within the left pane.
