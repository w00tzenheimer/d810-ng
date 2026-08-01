---
id: tcvpu-8p01
status: closed
deps: []
links: []
created: 2026-07-17T22:53:52Z
type: bug
priority: 2
assignee: w00tzenheimer
tags: [ui, x11]
---
# Replace configuration action glyphs with portable icons

Replace Unicode text glyphs on D-810 Configuration action buttons with portable Qt/IDA icon assets so duplicate and delete do not render as missing-glyph boxes in XQuartz.

## Acceptance Criteria

New, duplicate, edit, and delete controls use non-Unicode icon assets; tooltips remain the action authority; native XQuartz rendering shows no missing-glyph boxes.


## Notes

**2026-07-17T23:00:04Z**

Replaced all four D-810 configuration action glyphs with bundled SVG assets and updated package data. Fresh XQuartz IDA process rendered create, duplicate, edit, and delete correctly with no tofu boxes. Focused icon contracts and full unit suite are green.
