# contentauth-c2pa-claim

The C2PA v2 claim and its `COSE_Sign1` signature envelope as an independent
element. The claim holds `HashedUri`s — a URL and a digest each — never the
assertions, so this crate depends on no assertion crate, no JUMBF, no key
handling and no I/O. `Claim::encode` gives the CBOR; the `signature` module
gives the protected header, the exact bytes to sign, and the assembled
envelope. The signing is the host's.

**TODO:** the claim's `instanceID` should be the asset's `xmpMM:InstanceID`
when it has XMP (the spec's "should"). This crate cannot check; no caller in
this workspace, nor Gavin's `c2pa-core` sample, does either.
