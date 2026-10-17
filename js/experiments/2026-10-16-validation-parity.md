# Action-validation parity investigation

Migrated from the combined findings dated 2026-10-16. Measurements and test
counts below describe the original run, not a new execution.

## Findings

The malformed-action difference is reproducible without JavaScript, Workers or
Wasm. The differential test
[`known_gap_created_action_without_source_type_is_only_rejected_by_c2pa_rs`](../../c2pa-rs-compat-conformance/tests/v2_manifests.rs)
builds two freshly signed JPEGs through the workspace builder: the baseline
definition and the same definition with only `digitalSourceType` removed.
Both readers inspect exactly the same file in each case.
This investigation ran against the conformance harness's resolved c2pa-rs
**0.91.3**, independently reproducing the earlier SDK-binary observation.

| Check | Valid control | Missing `digitalSourceType` |
| --- | --- | --- |
| Workspace reader | `Valid` | `Valid` (known gap) |
| c2pa-rs active-manifest failures | `signingCredential.untrusted` | `signingCredential.untrusted` plus `assertion.action.malformed` |
| Signature, assertion hashes and asset hash | Pass in both readers | Pass in both readers |

No trust anchor is configured in this test; the pre-existing trust-policy
difference is explicit, not mistaken for the action-validation difference.
The test pins the **current divergence**, not desired compatibility. When action
validation is implemented, replace that expectation with rejection parity.

The mechanism is a missing validation layer:

1. The baseline definition converter encodes assertion data into CBOR; it does
   not enforce the semantic rules of each assertion type.
2. The reader's `read_manifest` checks required claim fields, assertion hashes,
   the claim signature, data-hash assertions and CAWG identity assertions.
   Ordinary action assertions are not dispatched to a semantic validator.
3. `check_assertion_hashes` proves the signed reference matches assertion bytes;
   it cannot establish that those bytes describe a conformant action.
4. The reference c2pa-rs validator separately runs `verify_actions`, including
   the required source type for `c2pa.created`. It also has other action rules
   (for example, nonempty action lists and ingredient relationships); this
   investigation does not establish parity for those rules. Its v1 strictness
   setting also affects which checks run, so a v2 rule must not simply be
   imposed on all historical claims.

Existing positive round trips and hash-tamper tests did not exercise this
negative semantic case. A builder and reader sharing the same omission can
agree while an independent validator disagrees. The narrow benchmark therefore
remains an unequal-validation comparison. No timing difference has been
attributed quantitatively to this missing check.

The correct future fix belongs in the domain reader, shared by every host,
with version-aware action decoding, status emission and failure classification.
Adding just a JS guard or a status-code constant would not fix signed input
from other producers. Builder-side definition checks may improve feedback but
cannot replace read-side validation. Product behavior is unchanged by this
investigation; it adds a differential characterization test.

From the repository root, reproduce the investigation and its existing v1/v2 controls:

```sh
cargo test --manifest-path c2pa-rs-compat-conformance/Cargo.toml --test v2_manifests
```

[All experiment reports](README.md)
