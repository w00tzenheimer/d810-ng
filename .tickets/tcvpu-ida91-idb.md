---
id: tcvpu-ida91-idb
status: closed
deps: []
links: []
created: 2026-07-18T00:00:00Z
type: task
priority: 1
assignee: w00tzenheimer
---
# Create a reusable IDA 9.1 database for the libobfuscated fixture

Seed a database headlessly with the IDA 9.1 `idapro`/IDALIB runtime from a
copied raw DLL, reopen it with that same runtime, and promote only the verified
database to `samples/bins/libobfuscated.dll.ida91.i64`. Preserve the raw source
fixture unchanged and do not use the GUI for database creation.

## Evidence

- IDA 9.1's Linux image exposes `idapro` over `/app/ida/libidalib.so`.
  `open_database(path, True)` completed analysis, and `close_database(True)`
  created the seed `.i64`.
- The promoted master is
  `/Users/mahmoud/src/idapro/d810/samples/bins/libobfuscated.dll.ida91.i64`
  (1,741,498 bytes, SHA-256
  `9d1073f6edec23f141dbb3cd6acf3584662777b54d6f0b459862780a3031e9bb`).
- A fresh IDA 9.1/IDALIB process reopened a writable copy with result `0`,
  found 273 functions, and closed with `close_database(False)`; neither the
  master nor raw source changed.
- The master is intentionally ignored by `.gitignore` with the rest of the
  user-supplied sample corpus. Launchers must mount it read-only, copy it to a
  disposable writable location, and open only that copy: IDALIB returned `4`
  when given the read-only mounted master directly.
