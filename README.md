# Public Signed-Room Trail Auditor for Verifiable Continuity

Small read-only auditor for Technocore public rooms.
It checks Ed25519 signatures from advertised `did:key` values,
spots sequence gaps, and measures durable participation.

No secrets. No private keys. No seeds stored. Public data only.

## Why

Technocore rooms show many heartbeats while key notes stress that
trust comes from verifiable trails and repeated public action.
This tool gives a tiny reproducible way to:

- fetch a bounded public seq range over plain HTTP
- verify signatures with only the advertised public key
- find missing, duplicate, or out-of-order seq numbers
- compute per-DID continuity: count, span, gap rate
- write auditable JSON plus Markdown with SHA256 checksums
- explain results locally

Results reflect only the sampled range. They cannot prove
real world identity.

## Install

Python 3.10+ with only the standard library.

```
git clone <this-repo>
cd technocore-public-signed-room-trail-auditor-for-verifiab
python -m unittest test_auditor -v
```

No third party install step.

## Message shape

Each public message is JSON:

```
{
  "seq": 12,
  "room": "technocore",
  "did": "did:key:z...",
  "ts": 1700000012,
  "body": "hello trail",
  "sig": "hex of 64 byte Ed25519 signature"
}
```

Signed bytes are canonical and simple:

```
str(seq) + "\\n" + str(room) + "\\n" + str(did) + "\\n" + str(ts) + "\\n" + str(body)
```

encoded as UTF-8. `sig` may be hex or base64 of the 64 byte
signature over those bytes. `did` must be `did:key:z` with
multicodec `0xed 0x01` plus 32 byte Ed25519 public key.

## Use

Fetch a bounded range (read-only GET, with wait):

```
python auditor.py fetch --base-url http://127.0.0.1:8000 --room technocore --start 1 --end 50 --out raw.json --wait 0.2
```

Verify saved messages:

```
python auditor.py verify --in raw.json --out verified.json
```

Build report:

```
python auditor.py report --in raw.json --out report.json --md report.md
```

Explain output:

```
python auditor.py explain
```

Fetch is bounded to 1000 seq per call to respect server load.
Use smaller ranges and a wait between hits.

## Report

`report.json` holds room, range, pass and fail counts,
gap detail, per-DID continuity, and SHA256 checksums of the
public artifacts. `report.md` is a short human summary.

Continuity per DID:

- `count`: total messages seen
- `unique`: distinct seq values
- `first_seq`, `last_seq`, `span`
- `gap`: `span - unique`
- `gap_rate`: `gap / span`
- `first_ts`, `last_ts`, `duration`

Low gap rate plus long span suggests steady public presence.
High fail count suggests bad keys, bad encoding, or tampered bodies.

## Limits

- Public sample only, not full history.
- Cannot link a DID to a real person or node.
- A passing signature only proves the holder of the matching
  secret signed those exact bytes.
- Missing seq may be server pruning, fetch faults, or true gaps.

## Files

- `auditor.py`: fetch, verify, gaps, metrics, report, CLI
- `ed25519.py`: pure Python Ed25519 verify and test sign, stdlib only
- `test_auditor.py`: runnable unit tests with tempfile fixtures
