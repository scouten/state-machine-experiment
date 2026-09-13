# C2PA specification reference snapshot

This folder contains a **snapshot** of the `.adoc` source files that make up
the [C2PA Technical Specification](https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html),
version 2.4. It is included so that this workspace's reader and builder
crates can be developed and reviewed against the exact specification text
they implement.

These files are **not** built, rendered, or otherwise compiled by anything in
this workspace. They are a static, pinned copy kept purely for reference —
grep them, link to a line from a doc comment, or read them side by side with
the code that implements a given clause.

## Source

| | |
| --- | --- |
| Project | C2PA (Coalition for Content Provenance and Authenticity) |
| Pinned version | `2.4` |
| Rendered spec | <https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html> |

The upstream `.adoc` source is maintained in a working repository that is
not publicly accessible; this snapshot was taken from that repository's `2.4`
tag by someone with access to it. Anyone without access to that repository
who needs to refresh this snapshot for a later version should ask a C2PA
member with access to do so, following the steps below.

## What is included

Only the `.adoc` source files that make up the specification text itself are
snapshotted here, at [`docs/modules/specs`](docs/modules/specs) — both the
`pages/C2PA_Specification.adoc` entry point (the general release) and
`pages/ContentCredentials.adoc` (the ISO-fast-track render of the same
content via the `partials/ISO/` includes), along with every `partials/` file
either one includes.

Not included, at least for now:

- Non-`.adoc` assets referenced by the spec (images, diagrams, the rendered
  PDF/XML, the schema zip) — the prose is the part worth having inline for
  reference; the rest is easy to view from the rendered spec online.
- The crJSON and soft-binding modules — separate, independently versioned
  specifications, not part of `C2PA_Specification.adoc` itself.
- Superseded pre-2.0 archived content no longer part of the current
  specification.

Any of these can be brought in later the same way, if a future task needs
them.

## How to update this snapshot

Whoever has access to the upstream working repository can refresh this
snapshot for a later version:

1. Check out the desired tag (e.g. `2.5`) of the upstream repository.
2. Replace the contents of [`docs/modules/specs`](docs/modules/specs) with
   that tag's `.adoc` files at the same relative path — for example:

   ```sh
   git -C /path/to/upstream/checkout ls-tree -r --name-only <tag> -- docs/modules/specs \
     | grep '\.adoc$' \
     | while read -r f; do
         mkdir -p "reference/c2pa-spec/$(dirname "$f")"
         git -C /path/to/upstream/checkout show "<tag>:$f" > "reference/c2pa-spec/$f"
       done
   ```

3. Update the **Pinned version** row above to match.
4. Review the diff for files added, removed, or renamed upstream.

## License

The C2PA specification text in [`docs/modules/specs`](docs/modules/specs) is
made available under the terms of a
[Creative Commons Attribution 4.0 International License](https://creativecommons.org/licenses/by/4.0/)
(CC-BY-4.0); see [`docs/modules/specs/partials/CCLicense.adoc`](docs/modules/specs/partials/CCLicense.adoc)
and [`docs/modules/specs/partials/PatentPolicy.adoc`](docs/modules/specs/partials/PatentPolicy.adoc)
for the license and patent policy text carried in the spec itself.

These license terms apply to the contents of this `reference/c2pa-spec`
folder only, and are separate from the MIT OR Apache-2.0 terms that cover the
rest of this repository.
