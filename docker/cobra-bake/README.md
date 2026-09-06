# CoBRA bake: the published d810-cobra wheel inside the IDA test images

The IDA test-runtime images used to compile d810-cobra from source during the
image build. d810-cobra 0.1.5 publishes cp313 manylinux wheels for both
`aarch64` and `x86_64`, so the image now installs the published wheel and
records its identity in labels, and the Docker test runner installs nothing at
all when it recognises those labels.

## What is tracked here, and why

The IDA image Dockerfile and the image build script live beside the licensed
IDA installers, in a directory that is outside git. Everything in this
directory is the tracked, reviewable half of that arrangement:

| file | role |
|-|-|
| `published_identity` | **the single source of truth**: version, per-arch wheel name + sha256, tag/core/parent commits. Nothing else declares them |
| `cobra_identity.sh` | reads `published_identity` into shell variables, plus the label comparison; sourced by the image build script |
| `stage_cobra_bake_context.sh` | copies the one architecture-matching published wheel, its `SHA256SUMS` line and the verifier into a Docker build context |
| `verify_cobra_install.py` | manifest + compiled-extension import + known-answer solve + identity assertions; run by the bake step, by the build script's verification table, and by hand |
| | `D810_COBRA_REQUIRE_SOLVE=0` selects the reduced check for an environment without d810, and asserts d810 really is absent |
| `Dockerfile.cobra-bake.fragment` | the exact `ARG` / `RUN` / `LABEL` block inserted into the image Dockerfile |

`Dockerfile.cobra-bake.fragment` is a copy, not an include: Docker has no
`#include`. Changing the bake means changing both it and the image Dockerfile.

`published_identity` is a whitespace-delimited table on purpose. It is the only
shape both bash (a `while read -r` loop -- no `jq`, no dependency, and no
shell-sourcing of a data file) and Python (`str.split`) parse without a second
copy or a parser: JSON would force `jq`, which is not guaranteed on the host,
or an `eval`-based shell hack. The Docker test runner
(`tools/scripts/run_system_tests_docker.sh`) reads the same file for its
accepted-wheel table and its pinned source revision, and both readers fail
closed when it is missing or malformed. `tests/unit/tools/test_cobra_bake.py`
asserts that neither reader carries a literal copy, so editing one alone is a
test failure rather than a silent desync.

## Labels

A `SPEEDUPS=1` image carries all five:

    org.d810.cobra.version        0.1.5
    org.d810.cobra.wheel_sha256   <published sha256 for this image's arch>
    org.d810.cobra.tag_commit     73b405c106d78e1fdc7576b217de39b7dcd0ddb3
    org.d810.cobra.core_commit    72f616f822f538a0cfbea3c880f9d1e68bb9a8f1
    org.d810.cobra.parent_commit  3b3c406270f1efd8e222f0b05040ae4e074b27d5

A vanilla image carries all five EMPTY. There is no valid third state: the
runner treats a partially filled set as a hard error, because that is exactly
the state in which a consumer would believe a published wheel is installed
when nothing is.

`parent_commit` is the d810-cobra source revision the runner pins for source
builds. The runner refuses a baked image whose `parent_commit` does not equal
its own pin, so a baked run and a source-built run always describe the same
upstream code.

## The two wheel identities

The preflight wheels built before the 0.1.5 release share their filenames AND
their sizes with the published ones, and differ only in their bytes. They are
provenance evidence and are never an accepted production identity here. Only
the two hashes in `published_identity` are.

## The image build script

`tools/scripts/build_ida_images.sh` (untracked, beside the installers) sources
`cobra_identity.sh`, calls `stage_cobra_bake_context.sh` to put the one
architecture-matching wheel into the build context, and passes the five
`--build-arg` values for `SPEEDUPS=1` variants only. It takes
`--cobra-wheel-dir DIR` to point at the published wheels.

It reads this directory from the repository root, two levels above itself, so
the identity, the staging helper and the verifier are under version control
even though the script is not.

Which architecture it builds is decided by the installer, not by a flag. For
9.4 the x86-64 installer is `_gitless/resource/9.4/ida9.4.run`, so `-v 9.4`
alone builds `linux/amd64`; the arm64 installer sits beside it as
`ida9.4.run.arm64` and the arm64 image is built from its own resource
directory, `-v 9.4 -r _gitless/resource/9.4-arm64`. The platform still comes
from the installer's ELF header, so the resource directory is what selects it.

Every build re-points the local `:latest` tag at the `:cli` image it just
produced. Two architectures cannot hold one tag, so
`idapro-9.4-speedups:latest` resolves to whichever was built last -- which is
also why the runner reads the CoBRA labels from the engine that will run the
container rather than trusting a tag.

Its verification table gains a `COBRA` column, which fails the run non-zero on
any mismatch:

- a speedups image must carry labels that match the published record for its
  architecture, and must then pass `verify_cobra_install.py` in a container --
  a build can succeed with a `--build-arg` that never reached the stage, and
  an image can carry correct labels over a broken install, so both are checked.
  That container gets this repository's `src/` mounted read-only on
  `PYTHONPATH`, because the solve needs d810 (see below);
- a vanilla image must carry no CoBRA claim at all, because a mislabelled
  vanilla image would make the runner skip an install that never happened.

## Where the known-answer solve can and cannot run

The image contains no d810: it is mounted at run time, and installing it would
shadow the mounted tree. `d810_cobra.solve` imports `d810.core` at module
scope, and `d810_cobra.prove` needs the `z3` that only `import d810` puts on
`sys.path`. So the solve is not reachable during the image build, and the bake
step runs the reduced check -- manifest, compiled extension, wheel identity --
with `D810_COBRA_REQUIRE_SOLVE=0`.

That flag is a declaration, not a mute button: the reduced mode asserts that
`d810` is genuinely not importable, so setting it anywhere the solve could have
run fails instead of passing quietly.

The solve is then enforced twice, in the two places d810 exists:

- the build script's verification table, immediately after the build, in a
  container of the image with `src/` mounted;
- the test runner's baked-mode setup stage, on every run.

## Verifying a baked image by hand

    docker run --rm -e D810_COBRA_EXPECT_VERSION=0.1.5 \
      -v "$PWD/src:/d810-src:ro" -e PYTHONPATH=/d810-src \
      -v "$PWD/docker/cobra-bake/verify_cobra_install.py:/verify.py:ro" \
      <image> /verify.py

Without the `src/` mount the same command needs
`-e D810_COBRA_REQUIRE_SOLVE=0`, and then proves identity only.
