"""Public signed-room trail auditor. Read-only, stdlib only."""
import argparse
import base64
import hashlib
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
import ed25519

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

EXPLAIN_TEXT = """Public Signed-Room Trail Auditor: how to read results.

PASS means: did:key decoded, sig decoded to 64 bytes, and
Ed25519 verify of canonical bytes succeeded.

FAIL reasons:
- bad did: not did:key:z with ed25519 multicodec
- bad sig encoding: not hex or base64 for 64 bytes
- bad signature: bytes do not match public key and payload
- missing field: seq, room, did, ts, body, or sig absent
- fetch error: HTTP read failed for that seq

GAPS:
- missing: seq numbers absent between min and max sampled
- duplicates: same seq seen more than once
- out_of_order: arrival order differs from sorted order

CONTINUITY per DID:
- count, unique, span, gap, gap_rate
- gap_rate = gap / span, lower is steadier
- duration = last_ts - first_ts when ts values are ints

ACTIONS:
- fails with bad signature: check body, ts, room spelling, and
  canonical join with newline separators.
- many missing: shrink range, retry with larger wait, check
  server pruning policy.
- duplicates: check fetcher retries or server replays.
- new operator: look for long span plus low gap_rate plus
  high pass rate before trusting continuity.

LIMITS: sampled public history only. Pass cannot prove real
world identity. No secrets are needed or stored.
"""


def b58_encode(data):
    if len(data) == 0:
        return ""
    n = int.from_bytes(data, "big")
    out = ""
    while n > 0:
        n, r = divmod(n, 58)
        out = B58[r] + out
    pad = 0
    for b in data:
        if b == 0:
            pad += 1
        else:
            break
    if out == "":
        return B58[0] * pad
    return B58[0] * pad + out


def b58_decode(s):
    if s == "":
        return b""
    n = 0
    for ch in s:
        idx = B58.find(ch)
        if idx < 0:
            raise ValueError("bad base58 char")
        n = n * 58 + idx
    size = (n.bit_length() + 7) // 8
    raw = n.to_bytes(size, "big") if size > 0 else b""
    pad = 0
    for ch in s:
        if ch == B58[0]:
            pad += 1
        else:
            break
    return b"\x00" * pad + raw


def pubkey_to_did(pubkey):
    if len(pubkey) != 32:
        raise ValueError("pubkey must be 32 bytes")
    raw = bytes([0xed, 0x01]) + pubkey
    return "did:key:z" + b58_encode(raw)


def did_to_pubkey(did):
    head = "did:key:z"
    if not did.startswith(head):
        raise ValueError("only did:key:z supported")
    enc = did[len(head):]
    raw = b58_decode(enc)
    if len(raw) != 34:
        raise ValueError("bad did length")
    if raw[0] != 0xed or raw[1] != 0x01:
        raise ValueError("bad multicodec")
    return raw[2:]


def signed_bytes(msg):
    seq = str(msg.get("seq", ""))
    room = str(msg.get("room", ""))
    did = str(msg.get("did", ""))
    ts = str(msg.get("ts", ""))
    body = str(msg.get("body", ""))
    text = seq + "\n" + room + "\n" + did + "\n" + ts + "\n" + body
    return text.encode("utf-8")


def decode_signature(sig_str):
    if not isinstance(sig_str, str):
        raise ValueError("sig must be string")
    s = sig_str.strip()
    is_hex = len(s) % 2 == 0 and len(s) > 0
    if is_hex:
        ok = True
        for c in s:
            if c not in "0123456789abcdefABCDEF":
                ok = False
                break
        if ok:
            try:
                raw = bytes.fromhex(s)
                if len(raw) == 64:
                    return raw
            except Exception:
                pass
    try:
        raw = base64.b64decode(s, validate=True)
        return raw
    except Exception:
        pass
    try:
        pad_needed = (-len(s)) % 4
        s2 = s + ("=" * pad_needed)
        raw = base64.urlsafe_b64decode(s2)
        return raw
    except Exception:
        pass
    raise ValueError("cannot decode signature")


def verify_one(msg):
    seq = msg.get("seq") if isinstance(msg, dict) else None
    did = ""
    if isinstance(msg, dict):
        v = msg.get("did")
        if isinstance(v, str):
            did = v
    if not isinstance(msg, dict):
        return {"seq": None, "did": "", "ok": False, "reason": "not a dict"}
    if "_fetch_error" in msg:
        return {"seq": seq, "did": did, "ok": False, "reason": "fetch error"}
    for field in ("seq", "room", "did", "ts", "body", "sig"):
        if field not in msg:
            return {"seq": seq, "did": did, "ok": False, "reason": "missing " + field}
    try:
        pub = did_to_pubkey(msg["did"])
    except Exception:
        return {"seq": seq, "did": did, "ok": False, "reason": "bad did"}
    try:
        sig = decode_signature(msg["sig"])
    except Exception:
        return {"seq": seq, "did": did, "ok": False, "reason": "bad sig encoding"}
    if len(sig) != 64:
        return {"seq": seq, "did": did, "ok": False, "reason": "bad sig length"}
    payload = signed_bytes(msg)
    try:
        good = ed25519.verify(pub, payload, sig)
    except Exception:
        return {"seq": seq, "did": did, "ok": False, "reason": "verify error"}
    if good:
        return {"seq": seq, "did": did, "ok": True, "reason": "pass"}
    return {"seq": seq, "did": did, "ok": False, "reason": "bad signature"}


def verify_all(messages):
    out = []
    for m in messages:
        out.append(verify_one(m))
    return out


def analyze_sequences(messages):
    seqs = []
    for m in messages:
        if isinstance(m, dict):
            s = m.get("seq")
            if isinstance(s, int) and not isinstance(s, bool):
                seqs.append(s)
    counts = {}
    for s in seqs:
        counts[s] = counts.get(s, 0) + 1
    dups = sorted([k for k, v in counts.items() if v > 1])
    ordered = sorted(seqs)
    ooo = seqs != ordered
    missing = []
    mn = None
    mx = None
    if seqs:
        mn = min(seqs)
        mx = max(seqs)
        present = set(seqs)
        for i in range(mn, mx + 1):
            if i not in present:
                missing.append(i)
    return {
        "missing": missing,
        "duplicates": dups,
        "out_of_order": ooo,
        "min_seq": mn,
        "max_seq": mx,
        "count": len(messages),
    }


def continuity_metrics(messages):
    groups = {}
    for m in messages:
        if not isinstance(m, dict):
            continue
        did = m.get("did")
        seq = m.get("seq")
        if not isinstance(did, str):
            continue
        if not isinstance(seq, int) or isinstance(seq, bool):
            continue
        g = groups.get(did)
        if g is None:
            g = {"seqs": [], "ts_vals": []}
            groups[did] = g
        g["seqs"].append(seq)
        ts = m.get("ts")
        tval = None
        if isinstance(ts, int) and not isinstance(ts, bool):
            tval = ts
        elif isinstance(ts, str):
            st = ts.strip()
            if st != "" and st.lstrip("-").isdigit():
                try:
                    tval = int(st)
                except Exception:
                    tval = None
        if tval is not None:
            g["ts_vals"].append(tval)
    result = {}
    for did, g in groups.items():
        uniq = sorted(set(g["seqs"]))
        count = len(g["seqs"])
        first = uniq[0]
        last = uniq[-1]
        span = last - first + 1
        gap = span - len(uniq)
        rate = (gap / span) if span > 0 else 0.0
        ts_vals = sorted(g["ts_vals"])
        if ts_vals:
            first_ts = ts_vals[0]
            last_ts = ts_vals[-1]
            duration = last_ts - first_ts
        else:
            first_ts = None
            last_ts = None
            duration = None
        result[did] = {
            "count": count,
            "unique": len(uniq),
            "first_seq": first,
            "last_seq": last,
            "span": span,
            "gap": gap,
            "gap_rate": rate,
            "first_ts": first_ts,
            "last_ts": last_ts,
            "duration": duration,
        }
    return result


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def canonical_json(obj):
    txt = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return txt.encode("utf-8")


def build_report(room, messages, verifications):
    gaps = analyze_sequences(messages)
    metrics = continuity_metrics(messages)
    passed = 0
    for v in verifications:
        if v.get("ok"):
            passed += 1
    failed = len(verifications) - passed
    msg_bytes = canonical_json(messages)
    ver_bytes = canonical_json(verifications)
    checks = {
        "messages_sha256": sha256_hex(msg_bytes),
        "verifications_sha256": sha256_hex(ver_bytes),
    }
    report = {
        "room": room,
        "sampled_count": len(messages),
        "range": {"min_seq": gaps["min_seq"], "max_seq": gaps["max_seq"]},
        "verification": {"passed": passed, "failed": failed, "total": len(verifications)},
        "gaps": gaps,
        "continuity": metrics,
        "checksums": checks,
        "note": "Sampled public history only; cannot prove real-world identity.",
    }
    core = canonical_json(report)
    report["report_sha256"] = sha256_hex(core)
    return report


def render_markdown(report):
    lines = []
    lines.append("# Trail audit: " + str(report.get("room", "")))
    lines.append("")
    rng = report.get("range", {})
    lines.append("Sampled: " + str(report.get("sampled_count", 0)))
    lines.append("Range: " + str(rng.get("min_seq")) + " to " + str(rng.get("max_seq")))
    ver = report.get("verification", {})
    lines.append("Passed: " + str(ver.get("passed", 0)) + " Failed: " + str(ver.get("failed", 0)))
    lines.append("")
    gaps = report.get("gaps", {})
    lines.append("## Gaps")
    lines.append("Missing: " + str(gaps.get("missing", [])))
    lines.append("Duplicates: " + str(gaps.get("duplicates", [])))
    lines.append("Out of order: " + str(gaps.get("out_of_order", False)))
    lines.append("")
    lines.append("## Continuity per DID")
    cont = report.get("continuity", {})
    if not cont:
        lines.append("No DIDs sampled.")
    for did in sorted(cont.keys()):
        c = cont[did]
        line = "- " + did + " count=" + str(c["count"])
        line = line + " span=" + str(c["span"]) + " gap_rate=" + str(round(c["gap_rate"], 4))
        line = line + " range=" + str(c["first_seq"]) + "-" + str(c["last_seq"])
        lines.append(line)
    lines.append("")
    lines.append("## Checksums")
    checks = report.get("checksums", {})
    lines.append("messages_sha256: " + str(checks.get("messages_sha256", "")))
    lines.append("verifications_sha256: " + str(checks.get("verifications_sha256", "")))
    lines.append("report_sha256: " + str(report.get("report_sha256", "")))
    lines.append("")
    lines.append(str(report.get("note", "")))
    return "\n".join(lines) + "\n"


def fetch_range(base_url, room, start, end, wait_sec=0.2, timeout=10):
    if start > end:
        raise ValueError("start must be <= end")
    if end - start > 1000:
        raise ValueError("range too large, keep <= 1000")
    if wait_sec < 0:
        wait_sec = 0
    base = base_url.rstrip("/")
    out = []
    for seq in range(start, end + 1):
        qs = urllib.parse.urlencode({"room": room, "seq": seq})
        url = base + "/messages?" + qs
        req = urllib.request.Request(url, method="GET", headers={"Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8")
                obj = json.loads(raw)
                if isinstance(obj, dict) and "seq" in obj:
                    out.append(obj)
                elif isinstance(obj, dict) and isinstance(obj.get("message"), dict):
                    out.append(obj["message"])
                else:
                    out.append({"seq": seq, "room": room, "_fetch_error": "unexpected shape"})
        except Exception as e:
            out.append({"seq": seq, "room": room, "_fetch_error": str(e)[:200]})
        if wait_sec and seq != end:
            time.sleep(wait_sec)
    return out


def save_json(obj, path):
    p = Path(path)
    p.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_json(path):
    p = Path(path)
    return json.loads(p.read_text(encoding="utf-8"))


def main(argv=None):
    ap = argparse.ArgumentParser(description="Public signed-room trail auditor")
    sub = ap.add_subparsers(dest="cmd", required=True)
    f = sub.add_parser("fetch", help="fetch public range")
    f.add_argument("--base-url", required=True)
    f.add_argument("--room", required=True)
    f.add_argument("--start", type=int, required=True)
    f.add_argument("--end", type=int, required=True)
    f.add_argument("--out", required=True)
    f.add_argument("--wait", type=float, default=0.2)
    f.add_argument("--timeout", type=float, default=10.0)
    v = sub.add_parser("verify", help="verify saved messages")
    v.add_argument("--in", dest="inp", required=True)
    v.add_argument("--out", required=False, default="")
    r = sub.add_parser("report", help="build audit report")
    r.add_argument("--in", dest="inp", required=True)
    r.add_argument("--room", required=False, default="")
    r.add_argument("--out", required=True)
    r.add_argument("--md", required=False, default="")
    sub.add_parser("explain", help="print guidance")
    args = ap.parse_args(argv)
    if args.cmd == "fetch":
        msgs = fetch_range(args.base_url, args.room, args.start, args.end, args.wait, args.timeout)
        save_json(msgs, args.out)
        print("saved " + str(len(msgs)) + " to " + args.out)
        return 0
    if args.cmd == "verify":
        msgs = load_json(args.inp)
        res = verify_all(msgs)
        passed = sum(1 for x in res if x.get("ok"))
        print("passed " + str(passed) + " of " + str(len(res)))
        if args.out != "":
            save_json(res, args.out)
            print("saved to " + args.out)
        else:
            print(json.dumps(res, indent=2, sort_keys=True))
        return 0
    if args.cmd == "report":
        msgs = load_json(args.inp)
        room = args.room
        if room == "":
            if msgs and isinstance(msgs[0], dict) and "room" in msgs[0]:
                room = str(msgs[0].get("room"))
            else:
                room = "unknown"
        res = verify_all(msgs)
        rep = build_report(room, msgs, res)
        save_json(rep, args.out)
        print("wrote " + args.out)
        if args.md != "":
            Path(args.md).write_text(render_markdown(rep), encoding="utf-8")
            print("wrote " + args.md)
        return 0
    if args.cmd == "explain":
        print(EXPLAIN_TEXT)
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
