# Introduction

## What is D-810 ng

D-810 ng (Next Generation) is an IDA Pro plugin which can be used to deobfuscate code at decompilation time by modifying IDA Pro microcode.
It was designed with the following goals in mind:

* It should have as least as possible impact on our standard reverse engineering workflow
  * Fully integrated to IDA Pro
* It should be easily extensible and configurable
  * Fast creation of new deobfuscation rules
  * Configurable so that we don't have to modify the source code to use rules for a specific project
* Performance impact should be reasonable
  * Our goal is to be transparent for the reverse engineer
  * But we don't care if the decompilation of a function takes 1 more second if the resulting code is much simpler.

## Installation

**Only IDA v9 or later is supported with Python 3.10 and higher** (since we need the microcode Python API)

Copy the contents of this repository to `.idapro/plugins` or `%appdata%\Hex-Rays\IDA pro\plugins`.

It is recommended to install Z3 to be able to use several features of D-810:

```bash
pip3 install z3-solver
```

## Using D-810 ng

* Load the plugin by using the `Ctrl-Shift-D` shortcut, you should see this configuration GUI

!["Configuration Gui"](./docs/source/images/gui_plugin_configuration.png "Configuration GUI")

* Choose or create your project configuration
  * If you are not sure what to do here, leave *default_instruction_only.json*.
* Click on the `Start` button to enable deobfuscation
* Decompile an obfuscated function, the code should be simplified (hopefully)
* When you want to disable deobfuscation, just click on the `Stop` button.

### Test Runner

D-810 ng comes with a built-in test runner that automatically loads system tests from the tests folder, under `tests/system`. This GUI is a simple test runner that allows a developer to run tests *inside* of IDA Pro, accessing the hexrays decompiler API and utilizing specific samples under `samples/bins` to test transformations.

The test runner is self-explanatory:

!["Test Runner Example"](./docs/source/images/test_runner_example-01.png "Test Runner Example")

Test reloading exists without needing to restart `IDA Pro` and you can execute different part of the tests via the testing context menu:

!["Test Runner Context Menu"](./docs/source/images/test_runner_example-ctx-menu.png "Test Runner Context Menu")

## Examples

In `samples/src`, there are various `C` programs compiled using the `samples/src/Makefile` into a shared library, without optimizations (`-O0`). On Windows, that shared library is a `.dll`, on Darwin(Mac)/Linux, it is a `.so`. Included is an example compiled dll, `libobfuscated.dll`, that can serve as a testing ground for seeing the plugin in action. Please make a pull request with more obfuscation `C` examples to build a repository of obfuscated sample code for further research.

### Test Constant Simplifications

**Before**: !["Before"](./docs/source/images/test_cst_simplification_before.png "Before Plugin")

**After**: !["After"](./docs/source/images/test_cst_simplification_after.png "After Plugin")

### Test XOR Simplifications

**Before**: !["Before"](./docs/source/images/test_xor_before.png "Before Plugin")

**After**: !["After"](./docs/source/images/test_xor_after.png "After Plugin")

## Warnings

This plugin is still in early stage of development, so issues ~~may~~ will happen.

* Modifying incorrectly IDA microcode may lead IDA to crash. We try to detect that as much as possible to avoid crash, but since it may still happen **save you IDA database often**
* Plugin is tested on Windows, Mac and Linux.

## Documentation

Work in progress

Currently, you can read our [blog post](https://eshard.com/posts/) to get some information.

## Licenses

This library is licensed under LGPL V3 license. See the [LICENSE](LICENSE) file for details.

## Authors

See [AUTHORS](AUTHORS.md) for the list of contributors to the project.

## Acknowledgement

Rolf Rolles for the huge work he has done with his [HexRaysDeob plugin](https://github.com/RolfRolles/HexRaysDeob) and all the information about Hex-Rays microcode internals described in his [blog post](https://www.hex-rays.com/blog/hex-rays-microcode-api-vs-obfuscating-compiler/). We are still using some part of his plugin in D-810.

Dennis Elser for the [genmc plugin](https://github.com/patois/genmc) plugin which was very helpful for debugging D-810 errors.

A special thank you to [Boris Batteux](https://gitlab.com/borisbatteux) for this great plugin!
