# C2PA specification reference snapshot

This folder contains a **snapshot** of the `.adoc` source files that make up
the [C2PA Technical Specification](https://c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html),
imported from the `c2pa-org/specs-core` repository. It is included so that
this workspace's reader and builder crates can be developed and reviewed
against the exact specification text they implement.

These files are **not** built, rendered, or otherwise compiled by anything in
this workspace. They are a static, pinned copy kept purely for reference —
grep them, link to a line from a doc comment, or read them side by side with
the code that implements a given clause.

## Source

| | |
| --- | --- |
| Project | C2PA (Coalition for Content Provenance and Authenticity) |
| Upstream repository | `c2pa-org/specs-core` (private) |
| Pinned tag | `2.4` |
| Pinned commit | `712d8baf6c7c482d754dce5919f7f4f4b443d7e6` |
| Commit date | 2026-04-01 |

## What is included

Only the `.adoc` source files under the upstream `docs/modules/specs/`
directory are snapshotted here, at the same relative path (i.e.
[`docs/modules/specs`](docs/modules/specs)). This is the specification text
itself — both the `pages/C2PA_Specification.adoc` entry point (the general
release) and `pages/ContentCredentials.adoc` (the ISO-fast-track render of
the same content via the `partials/ISO/` includes) — along with every
`partials/` file either one includes.

Not included, at least for now:

- Non-`.adoc` assets referenced by the spec (images, diagrams, the rendered
  PDF/XML, the schema zip) — the prose is the part worth having inline for
  reference; the rest is easy to view from the rendered spec online.
- `docs/modules/crJSON` and `docs/modules/softbinding` — separate,
  independently versioned specifications, not part of `C2PA_Specification.adoc`
  itself.
- `archived/` — superseded pre-2.0 content no longer part of the current
  specification.

Any of these can be brought in later the same way, if a future task needs
them.

## How to update this snapshot

1. In a checkout of `c2pa-org/specs-core`, find the desired tag (e.g. `2.5`).
2. Replace the contents of [`docs/modules/specs`](docs/modules/specs) with
   that tag's `.adoc` files at the same path — for example:

   ```sh
   git -C /path/to/specs-core ls-tree -r --name-only <tag> -- docs/modules/specs \
     | grep '\.adoc$' \
     | while read -r f; do
         mkdir -p "reference/c2pa-specs-core/$(dirname "$f")"
         git -C /path/to/specs-core show "<tag>:$f" > "reference/c2pa-specs-core/$f"
       done
   ```

3. Update the **Pinned tag**, **Pinned commit**, and **Commit date** rows
   above to match.
4. Review the diff for files added, removed, or renamed upstream.

## License

The C2PA specification text in [`docs/modules/specs`](docs/modules/specs) is
made available under the terms of a
[Creative Commons Attribution 4.0 International License](https://creativecommons.org/licenses/by/4.0/)
(CC-BY-4.0); see [`docs/modules/specs/partials/CCLicense.adoc`](docs/modules/specs/partials/CCLicense.adoc)
and [`docs/modules/specs/partials/PatentPolicy.adoc`](docs/modules/specs/partials/PatentPolicy.adoc)
for the license and patent policy text carried in the spec itself.

These license terms apply to the contents of this `reference/c2pa-specs-core`
folder only, and are separate from the MIT OR Apache-2.0 terms that cover the
rest of this repository.
