# contentauth-c2pa-assertion-actions

The `c2pa.actions.v2` assertion as an independent, composable element: a
deliberate subset of `actions-map-v2` in, an `EncodedAssertion` (label plus
opaque CBOR) out. No session — nothing here needs the host. It refuses to
encode what a validator would refuse (no actions, an unnamed action, a
`c2pa.created` with no `digitalSourceType`).
