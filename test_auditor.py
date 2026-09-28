import base64
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
import auditor
import ed25519


def make_seed(tag):
    return hashlib.sha256(tag.encode("utf-8")).digest()


def make_msg(seq, room, did, ts, body, seed):
    tmp = {"seq": seq, "room": room, "did": did, "ts": ts, "body": body}
    payload = auditor.signed_bytes(tmp)
    sig = ed25519.sign(seed, payload)
    tmp["sig"] = sig.hex()
    return tmp


class TestDidKey(unittest.TestCase):
    def test_roundtrip(self):
        seed = make_seed("did-roundtrip-1")
        pub = ed25519.pubkey_from_seed(seed)
        did = auditor.pubkey_to_did(pub)
        back = auditor.did_to_pubkey(did)
        self.assertEqual(pub, back)
        self.assertTrue(did.startswith("did:key:z"))

    def test_rejects_bad_prefix(self):
        with self.assertRaises(ValueError):
            auditor.did_to_pubkey("did:other:z123")

    def test_rejects_bad_char(self):
        with self.assertRaises(ValueError):
            auditor.did_to_pubkey("did:key:z0*bad")


class TestCurve(unittest.TestCase):
    def test_base_order(self):
        ident = ed25519.scalarmult(ed25519.BASE, ed25519.L)
        enc = ed25519.encode_point(ident)
        self.assertEqual(enc, bytes.fromhex("0100000000000000000000000000000000000000000000000000000000000000"))

    def test_encode_decode(self):
        seed = make_seed("encode-decode")
        pub = ed25519.pubkey_from_seed(seed)
        pt = ed25519.decode_point(pub)
        self.assertIsNotNone(pt)
        enc = ed25519.encode_point(pt)
        self.assertEqual(enc, pub)

    def test_sign_verify(self):
        seed = make_seed("sign-verify")
        pub = ed25519.pubkey_from_seed(seed)
        msg = b"hello technocore trail"
        sig = ed25519.sign(seed, msg)
        self.assertEqual(len(sig), 64)
        self.assertTrue(ed25519.verify(pub, msg, sig))

    def test_tamper(self):
        seed = make_seed("tamper")
        pub = ed25519.pubkey_from_seed(seed)
        sig = ed25519.sign(seed, b"orig")
        self.assertFalse(ed25519.verify(pub, b"other", sig))

    def test_wrong_key(self):
        s1 = make_seed("key-one")
        s2 = make_seed("key-two")
        p2 = ed25519.pubkey_from_seed(s2)
        sig = ed25519.sign(s1, b"data")
        self.assertFalse(ed25519.verify(p2, b"data", sig))


class TestVerify(unittest.TestCase):
    def test_verify_one_pass(self):
        seed = make_seed("verify-pass")
        pub = ed25519.pubkey_from_seed(seed)
        did = auditor.pubkey_to_did(pub)
        msg = make_msg(1, "technocore", did, 100, "steady", seed)
        res = auditor.verify_one(msg)
        self.assertTrue(res["ok"])
        self.assertEqual(res["reason"], "pass")

    def test_verify_one_tamper(self):
        seed = make_seed("verify-tamper")
        pub = ed25519.pubkey_from_seed(seed)
        did = auditor.pubkey_to_did(pub)
        msg = make_msg(2, "technocore", did, 101, "orig body", seed)
        msg["body"] = "changed body"
        res = auditor.verify_one(msg)
        self.assertFalse(res["ok"])
        self.assertEqual(res["reason"], "bad signature")

    def test_verify_missing_field(self):
        msg = {"seq": 1, "room": "technocore"}
        res = auditor.verify_one(msg)
        self.assertFalse(res["ok"])
        self.assertTrue(res["reason"].startswith("missing"))

    def test_verify_bad_did(self):
        msg = {"seq": 1, "room": "technocore", "did": "bad", "ts": 1, "body": "x", "sig": "00" * 64}
        res = auditor.verify_one(msg)
        self.assertFalse(res["ok"])
        self.assertEqual(res["reason"], "bad did")

    def test_base64_sig(self):
        seed = make_seed("b64-sig")
        pub = ed25519.pubkey_from_seed(seed)
        did = auditor.pubkey_to_did(pub)
        msg = make_msg(3, "technocore", did, 102, "b64", seed)
        raw = bytes.fromhex(msg["sig"])
        msg["sig"] = base64.b64encode(raw).decode("ascii")
        res = auditor.verify_one(msg)
        self.assertTrue(res["ok"])


class TestGaps(unittest.TestCase):
    def test_missing(self):
        msgs = [{"seq": 1}, {"seq": 2}, {"seq": 4}]
        g = auditor.analyze_sequences(msgs)
        self.assertEqual(g["missing"], [3])
        self.assertEqual(g["duplicates"], [])
        self.assertFalse(g["out_of_order"])

    def test_duplicates(self):
        msgs = [{"seq": 5}, {"seq": 5}, {"seq": 6}]
        g = auditor.analyze_sequences(msgs)
        self.assertEqual(g["duplicates"], [5])

    def test_out_of_order(self):
        msgs = [{"seq": 2}, {"seq": 1}]
        g = auditor.analyze_sequences(msgs)
        self.assertTrue(g["out_of_order"])


class TestMetrics(unittest.TestCase):
    def test_counts_and_gap_rate(self):
        s1 = make_seed("metrics-a")
        p1 = ed25519.pubkey_from_seed(s1)
        d1 = auditor.pubkey_to_did(p1)
        s2 = make_seed("metrics-b")
        p2 = ed25519.pubkey_from_seed(s2)
        d2 = auditor.pubkey_to_did(p2)
        msgs = [
            make_msg(1, "technocore", d1, 1000, "a", s1),
            make_msg(2, "technocore", d1, 1010, "b", s1),
            make_msg(4, "technocore", d1, 1030, "c", s1),
            make_msg(3, "technocore", d2, 1020, "d", s2),
        ]
        m = auditor.continuity_metrics(msgs)
        self.assertEqual(m[d1]["count"], 3)
        self.assertEqual(m[d1]["span"], 4)
        self.assertEqual(m[d1]["gap"], 1)
        self.assertAlmostEqual(m[d1]["gap_rate"], 0.25)
        self.assertEqual(m[d1]["duration"], 30)
        self.assertEqual(m[d2]["count"], 1)


class TestReport(unittest.TestCase):
    def test_build_and_checksums(self):
        seed = make_seed("report-1")
        pub = ed25519.pubkey_from_seed(seed)
        did = auditor.pubkey_to_did(pub)
        msgs = [
            make_msg(10, "technocore", did, 2000, "one", seed),
            make_msg(11, "technocore", did, 2010, "two", seed),
        ]
        ver = auditor.verify_all(msgs)
        rep = auditor.build_report("technocore", msgs, ver)
        self.assertEqual(rep["verification"]["passed"], 2)
        self.assertEqual(len(rep["checksums"]["messages_sha256"]), 64)
        self.assertEqual(len(rep["report_sha256"]), 64)
        md = auditor.render_markdown(rep)
        self.assertIn("technocore", md)
        self.assertIn("Passed", md)

    def test_save_load_tempfile(self):
        seed = make_seed("report-temp")
        pub = ed25519.pubkey_from_seed(seed)
        did = auditor.pubkey_to_did(pub)
        msgs = [make_msg(7, "technocore", did, 3000, "hi", seed)]
        ver = auditor.verify_all(msgs)
        rep = auditor.build_report("technocore", msgs, ver)
        with tempfile.TemporaryDirectory() as td:
            jp = Path(td) / "report.json"
            mp = Path(td) / "report.md"
            auditor.save_json(rep, str(jp))
            back = auditor.load_json(str(jp))
            self.assertEqual(back["room"], "technocore")
            mp.write_text(auditor.render_markdown(rep), encoding="utf-8")
            txt = mp.read_text(encoding="utf-8")
            self.assertIn("Checksums", txt)

    def test_canonical_stable(self):
        a = auditor.canonical_json({"b": 1, "a": 2})
        b = auditor.canonical_json({"a": 2, "b": 1})
        self.assertEqual(a, b)


class TestExplain(unittest.TestCase):
    def test_explain_text(self):
        self.assertIn("PASS", auditor.EXPLAIN_TEXT)
        self.assertIn("gap_rate", auditor.EXPLAIN_TEXT)


class TestFetchValidation(unittest.TestCase):
    def test_range_validation(self):
        with self.assertRaises(ValueError):
            auditor.fetch_range("http://127.0.0.1:9", "technocore", 5, 4)
        with self.assertRaises(ValueError):
            auditor.fetch_range("http://127.0.0.1:9", "technocore", 0, 2000)


if __name__ == "__main__":
    unittest.main()
