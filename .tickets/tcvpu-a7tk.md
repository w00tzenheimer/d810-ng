---
id: tcvpu-a7tk
status: closed
deps: []
links: []
created: 2026-07-17T23:04:11Z
type: bug
priority: 2
assignee: w00tzenheimer
tags: [ui, x11]
---
# Replace status and rule legend text markers with icons

Replace D-810 engine status and rule legend text glyphs with portable SVG/icon markers so their rendering does not depend on X11 font glyph coverage.

## Acceptance Criteria

Engine state uses visible non-text red/green markers; rule legend uses non-text enabled/disabled/configurable markers; native fresh XQuartz rendering has no text-star markers or missing glyphs.

