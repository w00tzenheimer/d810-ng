# Headless API

D-810 ng can be driven from IDAPython without loading the GUI plugin entry point
in `src/d810ng.py`. The headless API is deliberately small and reuses the normal
project configuration path:

- `configure()` loads a D-810 project.
- `start()` installs Hex-Rays optimization hooks.
- `stop()` removes those hooks.
- `status()` reports the active project and rule counts.

This API does not require environment flags, does not initialize the GUI plugin,
and does not mutate singleton internals. Install the package into IDA's Python
environment, then import `d810.headless` directly from your script.

During `configure()`, `d810.headless` deliberately uses the same package
discovery/reload helper as `src/d810ng.py`, but skips `d810.ui`. That loads
registry-backed optimizer modules for headless use without importing the GUI.

## Install Into IDA Python

Find IDA's bundled Python and install this checkout into that environment:

```bash
IDA_PYTHON=/path/to/ida-pro/python_standalone/bin/python3
$IDA_PYTHON -m pip install -e /path/to/d810
```

Optional Z3/speedup setup should follow the project-level speedup instructions
in `README.md`. Do not copy `src/d810ng.py` into IDA's plugin directory for
headless-only use; that file is the GUI plugin entry point.

Verify the API import from the same Python environment:

```bash
$IDA_PYTHON -c "from d810.headless import configure, start, stop, status; print(status())"
```

## Use From IDAPython

Run this inside IDA, `idat64`, `idalib`, or an automation layer that executes
IDAPython in a process with Hex-Rays available:

```python
from d810.headless import configure, start, status

configure(project="default_unflattening_ollvm.json")
start()

print(status())

import ida_hexrays

cfunc = ida_hexrays.decompile(0x401000)
print(str(cfunc))
```

Stop deobfuscation hooks when the script is done:

```python
from d810.headless import stop

stop()
```

## Custom Configuration

Use a directory containing `options.json`:

```python
from d810.headless import configure

configure(
    config_dir="/path/to/d810/config",
    project="default_unflattening_ollvm.json",
)
```

Or pass the `options.json` path directly:

```python
configure(
    config_path="/path/to/d810/config/options.json",
    project="my_project.json",
)
```

## Notes

- `configure()` must run before `start()`.
- `start()` is idempotent when hooks are already installed.
- `stop()` is a no-op when hooks are not installed.
- The API intentionally avoids installer behavior. IDA layouts differ across
  platforms and versions, so installation remains an explicit command sequence
  until supported layouts are defined.
