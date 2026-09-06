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
| `cobra_identity.sh` | the published identity (version, per-arch wheel name + sha256, tag/core/parent commits) and the label comparison, sourced by the image build script |
| `stage_cobra_bake_context.sh` | copies the one architecture-matching published wheel, its `SHA256SUMS` line and the verifier into a Docker build context |
| `verify_cobra_install.py` | manifest + compiled-extension import + known-answer solve + identity assertions; run by the bake step, by the build script's verification table, and by hand |
| `Dockerfile.cobra-bake.fragment` | the exact `ARG` / `RUN` / `LABEL` block inserted into the image Dockerfile |
| `SHA256SUMS.published` | the published hashes, in `sha256sum -c` form |

`Dockerfile.cobra-bake.fragment` is a copy, not an include: Docker has no
`#include`. Changing the bake means changing both it and the image Dockerfile.

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
the two hashes in `SHA256SUMS.published` are.

## Verifying a baked image by hand

    docker run --rm -e D810_COBRA_EXPECT_VERSION=0.1.5 \
      -v "$PWD/docker/cobra-bake/verify_cobra_install.py:/verify.py:ro" \
      <image> /verify.py
