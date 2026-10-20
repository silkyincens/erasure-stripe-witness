# ErasureStripeWitness

AI-assisted independent GenLayer IC prototype. It reconstructs bounded public polynomial data from encoded symbol vectors over GF(257), verifies **every** redundant vector, and gives consumers a currently active consistency receipt. It uses no LLM and holds no assets. No real public fixture, deployment, publication or live consensus is claimed.

## Purpose and exact model

An application with a public coefficient matrix can publish polynomial evaluations instead of original coefficients. This primitive independently reconstructs that matrix from k points and checks all supplied redundancy before owner activation. It certifies consistency of the **declared public symbols**, not which publisher or shard is trustworthy. This is not a generic file-hash bundle, Merkle proof, secret-sharing service, error-correcting decoder or promise of future data availability.

One exact-byte strict UTF8 JSON document contains the actual symbol vectors:

```json
{"version":1,"k":2,"shards":[{"x":1,"values":[8,9]},{"x":2,"values":[13,11]},{"x":3,"values":[18,13]},{"x":4,"values":[23,15]}]}
```

Field is fixed prime257. Version is exact integer1. Exact integer threshold k2..8; number of shards k+1..12, so at least one redundant point is required. Each shard has exactly x/values: x unique integer1..256; vectors share width1..16; symbols are integers0..256. Booleans are rejected as numbers. Unknown fields, duplicate JSON keys, NaN/Infinity, malformed UTF8, empty or >16384-byte bodies fail. Symbols are field elements, not necessarily bytes; no external binary-codec compatibility is asserted.

Sort points numerically by x, choose first k as a deterministic basis, and apply finite-field Lagrange interpolation separately to every column. Coefficients are ordered from constant term upwards; all arithmetic is modulo257. Every denominator is nonzero because x values are distinct; the inverse uses `pow(denominator,255,257)`. Evaluate each recovered polynomial at **every actual point and column**, not merely basis points. Result includes:

- `field`, `k`, `columns`, `basis_x` and `candidate_coefficients` (one k-coefficient row per column).
- `status`: CONSISTENT or INCONSISTENT, and `first_mismatch`: null or `{x,column,expected,observed}`, first by sorted x then zero-based column.
- `data_sha256`: only for CONSISTENT, SHA256 of canonical coefficient matrix JSON, not a recovered real-world file; null on inconsistency.

Canonical JSON uses sorted keys, compact separators, ASCII escaping and no nonfinite numbers. The example reconstructs columns `[3,5]` and `[7,2]`: polynomials3+5x and7+2x. It yields `[3,7]` at0 and `[232,150]` at200. Changing last shard's second symbol15→16 gives INCONSISTENT with x4/column1/expected15/observed16. A candidate derived from corrupted basis points is not identified as the original data. The contract neither repairs errors nor selects an authentic subset among inconsistent shards. A malicious author can provide a perfectly consistent but false codeword.

Leader and every validator fresh-fetch the document, require exact byte SHA, strictly validate all data, independently interpolate and verify every vector, and compare the complete canonical packet. No leader coefficients, success bit, mismatch shape or claimed digest can substitute for this computation. Packet binding includes protocol/chain/contract/owner/stripeID/URL+SHA/registration time/expected revision/certifier/certification time. Certificate ID hashes this full packet. Reordering equivalent input changes source SHA/certificate but preserves the derived coefficient-data hash.

## Interface and lifecycle

Constructor has **zero arguments**, fixing owner to deployer. IDs `[A-Za-z0-9_-]{1,32}`. URL exact `https://raw.githubusercontent.com/<owner>/<repo>/<40 lowercase hex>/<path>`, <=512 characters. Owner1..39 ASCII alphanumerics/single hyphens beginning/ending alphanumeric; repo1..100 ASCII alphanumerics/underscore/dot/hyphen, excluding `.` and `..`. File path1..192 safe ASCII `[A-Za-z0-9_.~/-]`, with no empty/dot/dotdot segments; no credentials, port, query, fragment, percent encoding or mutable ref. A name such as `.github` is allowed. SHA256 is64 lowercase hex. Actual Git object semantics/redirect targets are transport assumptions, not independently reconstructed.

| Method | Behavior |
|---|---|
| `register(stripe_id,source_url,source_sha256)` | Owner only, unused immutable record -> REGISTERED revision0. No fetch or validity claim yet. |
| `certify(stripe_id,expected_revision) -> str` | Anyone, REGISTERED0 only; independent complete source/interpolation -> CERTIFIED1; returns certificate ID. Negative mathematical result is also inspectable. |
| `activate(stripe_id,expected_revision,certificate_id)` | Owner, exact CERTIFIED1/certificate and CONSISTENT result only -> ACTIVE2. No refetch. |
| `revoke(stripe_id,expected_revision,reason)` | Owner, any nonREVOKED phase; offline terminal withdrawal, revision increments. |
| `get_stripe(stripe_id) -> dict` | Declaration, complete attestation, result, status/revision/certificate/history. Unknown ID reverts. |
| `is_active(stripe_id,certificate_id,expected_revision) -> bool` | Exact current ACTIVE receipt/revision, unknown ID false. |
| `verify_shard(stripe_id,expected_revision,certificate_id,x,values_json) -> bool` | Current ACTIVE only; x integer0..256, exact-width symbols0..256 in bounded JSON array <=512 chars; compares every certified column evaluation. Invalid input/unknown/inactive false. No fetch. |
| `get_configuration() -> dict` | Owner/protocol and bounds. |

Source x=0 is excluded from interpolation inputs; evaluation query x=0 is allowed to expose constant terms. `verify_shard` checks mathematical membership in the certified codeword, not that a new shard is actually hosted, authentic or delivered. Historical coefficients remain readable after revocation; current status governs accepted receipts, not access to public data.

There are8 lifetime records and at most4 phase events each. IDs/source declarations never reset, including after revoke; capacity does not recycle. Certification/activation are one-time, and any caller may become the first certifier. Only owner activates or revokes. Inconsistent certificates remain CERTIFIED1 and cannot activate; source failure preserves REGISTERED0 without certificate, permitting an exact-source retry or owner offline revoke. Revisions are exact integers, not bool. Reasons are trimmed nonempty1..200 characters. A different certificate/record/old revision cannot satisfy current ACTIVE.

Typical integration: publish a real public commit-pinned symbol document, calculate exact bytes SHA, owner register -> any `certify(id,0)` -> owner inspect all source/domain/result and `activate(id,1,certificate)` -> consumer reads exact coefficient data and current active status, then `verify_shard(id,2,certificate,200,"[232,150]")` for the example. This check does not authorize any real external action by itself.

## Reproduction and evidence

Python3.12, isolated environment; no wallet/RPC/browser:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe tools\verify.py
```

Official GenVM **v0.2.12**, runner `1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6`, stdlib `11rhn002yfajawsz7fai6mykznbxkxs6l91iskj5cm82c92qhy3v`; dependencies genlayer-test0.29.2, genvm-linter0.11.0, cloudpickle3.1.2. Initial SDK setup may fetch public artifacts. Whole tests run actual deployable code/storage/calldata/authorization and captured independent validator closures; only HTTP is mocked. Standalone conftest handles upstream Windows fd0 cleanup and official warp datetime metadata, replacing no finite-field algorithm. Tests assert literal coefficient vectors and simple known evaluations; there is no host interpolation solver.

Evidence retains **42 initial actual API failures** against a minimal deployed contract. Deliberately checking only basis points then caused **1 actual regression failure**; original production source was restored before full verification. Current whole-suite results/source hash and complete semantic lint/ABI extraction output are in `evidence/verification.json` and logs. Tests include GF wrap/inverse, all-redundancy mismatch/negative witness forgery, input-order canonicalization, valid k8/n12/width16/exact16384 bytes, strict schema/field/URL bounds, complete-shaped leader forgeries/fresh changed source, owner/CAS/certificate/history/capacity and revoked evaluation.

Fixtures are original MIT synthetic examples; `fixtures/source.json` explicitly records `test_url` for mocks and `public_url:null`, `live_source_verified:false`. A real demo requires separately publishing actual fixture bytes and using their real immutable URL/hash, then recording real receipts. The constructor is FINALIZED/SUCCESS on Studio 61999 with normal majority consensus, zero native value and exact tested on-chain source. See evidence/deployment.json; full live source retrieval and certification flow and non-Studio costs remain unverified. Independent read-only frozen-source root review closed; see `evidence/independent-review.json`.

## Limits and threat model

All symbols, coefficients, URLs and reasons are public; never submit secrets, Shamir shares, private documents or PII. Algebraic consistency cannot establish correct originals, ownership, licensing, authenticity, availability, secrecy or resistance to a malicious author supplying an entirely new consistent stripe. The fixed field and bounded coding format are deliberate protocol choices. SHA collision resistance, source transport and GenLayer consensus remain dependencies. SDK has no pre-download cap/final-URL/redirect enforcement; response caps are checked after download. Worst-case live VM gas is unmeasured. Business core is independently written finite-field interpolation/all-point verification; only SDK/HTTP/JSON/state primitives are shared with other contributions.

## Verified local result

Final full-package actual SDK suite: **43 passing tests**. Full official semantic lint and schema extraction exit0; ABI constructor has no parameters. Source hash is in evidence/verification.json and CONTRIBUTION.json. Independent read-only frozen-source review by `/root` closed without an important reproducible issue; see `evidence/independent-review.json`. Only documentation/evidence/package metadata changed after review; tests were not rerun during final closeout. This is local prototype review, not an audit. Only the constructor deployment is verified: `0xEf3f6e49b1c5c44B1aAcf08f3adF96b608716e39`. Complete live registration/certification/activation and real-source behavior remain unverified.
