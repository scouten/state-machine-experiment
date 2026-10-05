# 3. The read path

## Two sessions, nested

`ReadSession` (in `contentauth-c2pa-reader`) validates a manifest store but
has no idea what a JPEG is. `FileReadSession` (in `contentauth-c2pa-file-reader`)
wraps it with a format handler's `locate` operation, and **answers one of
the reader's requests itself**.

```mermaid
flowchart LR
    Host["Host<br/>(Read, Length, CurrentDateTime, Ocsp)"]
    subgraph FRS["FileReadSession"]
        direction TB
        Loc["handler.locate<br/><i>IoRequest: Read, Length</i>"]
        RS["ReadSession<br/><i>ManifestStore, AssetBytes,<br/>AssetLength, CurrentDateTime, Ocsp</i>"]
        Loc -- "manifest store bytes<br/>answers ManifestStore" --> RS
    end
    Host <-- "merged FileReadRequest" --> FRS
```

`ReadRequest::ManifestStore` never reaches the host. The host answers one
merged vocabulary — `FileReadRequest::{Read, Length, CurrentDateTime, Ocsp}`
— exactly as any other session's host would.

## What `ReadSession` validates

```mermaid
flowchart TD
    A[Manifest store bytes] --> B[JUMBF parse]
    B --> C[Claim decode<br/>v1 and v2 → one Claim type]
    C --> D[Assertion hashes<br/>vs claim]
    C --> E[Hard binding<br/>hash asset, excluding the store]
    C --> F[Claim signature<br/>COSE_Sign1]
    F --> G[Trust: chain to anchors,<br/>C2PA cert profile]
    F --> H[RFC 3161 timestamp<br/>can rescue expired cert]
    G --> I[Revocation, spec §15.9:<br/>stapled OCSP, then online]
    D & E & G & H & I --> V{{"Report:<br/>Trusted / Valid / Invalid<br/>+ status codes"}}
```

* **Integrity** — assertion hashes; the hard binding hashed in-crate from
  chunks the host streams (a window of concurrent 64 KiB reads).
* **Trust** — chain building against configured anchors; reports which
  trust list matched.
* **Timestamps** — a trusted RFC 3161 stamp keeps a since-expired signer
  valid.
* **Revocation** — OCSP only. Stapled first, then online (default on). An
  *unreachable* responder is fail-open; a response that is received and
  authenticated but doesn't affirmatively vouch counts as revoked.
* **v1 and v2 claims** decode into the same `Claim`; v2 required-field
  and self-redaction checks are enforced.

Not yet checked: ingredient manifests, remote manifest retrieval,
`assertion.notRedacted`.

## Request vocabulary (reader)

| Request | Purpose |
|---|---|
| `ManifestStore { stream }` | Get the JUMBF store out of the container |
| `AssetBytes { stream, range }` | Bytes for hard-binding verification |
| `AssetLength { stream }` | Needed since the binding names only what to *exclude* |
| `CurrentDateTime` | Cert validity windows; the crate reads no clock |
| `Ocsp { url, request_der }` | Host does only the HTTP POST |

Any request can be answered with `Failed`, but the outcome differs by
request. A host author should not treat an asset read failure as a normal
validation result:

| Request answered `Failed` | Outcome |
|---|---|
| `ManifestStore` | **Read stops** with `Error::HostFailure`; no report |
| `AssetBytes` | **Read stops** with `Error::HostFailure`; no report |
| `AssetLength` | Report is produced; the hard binding is recorded as not checked (`general.error`, "asset not available") |
| `CurrentDateTime` | Report is produced; trust is evaluated without a "now", so only signatures carrying a trusted timestamp can be fully evaluated |
| `Ocsp` | Report is produced. A CA certificate's unreachable responder is no finding; the signer's is recorded as `signingCredential.ocsp.inaccessible` |

In the builder, by contrast, every host failure is fatal.

## Three hosts for one session

```mermaid
flowchart LR
    S["FileReadSession<br/><i>one engine</i>"]
    S --- H1["read_manifest<br/>blocking Read + Seek<br/>file-reader"]
    S --- H2["Reader::with_file<br/>blocking + reqwest OCSP<br/>rs-compat"]
    S --- H3["Reader::from_blob<br/>async, Blob.slice().arrayBuffer()<br/>js-compat"]
    S --- H4["NodeSession<br/>sync calls, Node loop<br/>node-compat"]
```

See [Bindings](06-bindings.md).

**Next:** [The write path →](04-write-path.md)
