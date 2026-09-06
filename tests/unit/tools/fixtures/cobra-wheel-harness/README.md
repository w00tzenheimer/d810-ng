# d810-cobra harness fixture wheels

**These are NOT d810-cobra release artifacts and must never be treated as one.**

They are minimal, valid `.whl` files with recorded sha256 hashes. They carry a
`dist-info` and nothing else: no compiled extension, no code. They exist so the
Docker runner's wheel-mode unit tests have a file to hash, mount and name.

The published wheels are megabytes and live outside git, so on a checkout
without them every positive wheel-mode test used to skip -- and a skipped test
cannot notice that the directory it needs has been deleted.

The runner accepts one of these only when `D810_COBRA_HARNESS_WHEEL_SHA256`
names its hash. When it does, it prints a warning on stderr, its preamble says
`harness-fixture sha256 ...` instead of `published sha256 ...`, and the
provenance receipt records the fixture hash, which matches no published
artifact.

| file | sha256 |
|-|-|
| `d810_cobra-0.1.5-cp313-cp313-harness_fixture_aarch64.whl` | `bd5889898fa82481bdcf1e06c89f2559469bd76308fbcd9729c2e0bbfac4856b` |
| `d810_cobra-0.1.5-cp313-cp313-harness_fixture_x86_64.whl` | `43a2d7272d320c75d3212e53b5592a6f914a234a618eccc9932063896f7ee882` |

The platform tags (`harness_fixture_aarch64`, `harness_fixture_x86_64`) are
deliberately unlike any manylinux tag: a fixture must not be mistakable for a
published wheel by its filename either.
