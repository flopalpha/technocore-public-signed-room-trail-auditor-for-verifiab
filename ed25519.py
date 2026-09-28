"""Pure Python Ed25519 verify, stdlib only. Follows RFC 8032."""
import hashlib

Q = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493
DVAL = (-121665 * pow(121666, Q - 2, Q)) % Q
SQRT_M1 = pow(2, (Q - 1) // 4, Q)


def _inv(x):
    return pow(x, Q - 2, Q)


def xrecover(y):
    y = y % Q
    num = (y * y - 1) % Q
    den = (DVAL * y * y + 1) % Q
    xx = (num * _inv(den)) % Q
    x = pow(xx, (Q + 3) // 8, Q)
    if (x * x - xx) % Q != 0:
        x = (x * SQRT_M1) % Q
    if x % 2 != 0:
        x = Q - x
    return x


_BY = (4 * _inv(5)) % Q
_BX = xrecover(_BY)
BASE = (_BX, _BY, 1, (_BX * _BY) % Q)
IDENTITY = (0, 1, 1, 0)


def point_add(p, qpt):
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = qpt
    a = ((y1 - x1) * (y2 - x2)) % Q
    b = ((y1 + x1) * (y2 + x2)) % Q
    c = (t1 * 2 * DVAL % Q * t2) % Q
    d = (z1 * 2 % Q * z2) % Q
    e = (b - a) % Q
    f = (d - c) % Q
    g = (d + c) % Q
    h = (b + a) % Q
    x3 = (e * f) % Q
    y3 = (g * h) % Q
    z3 = (f * g) % Q
    t3 = (e * h) % Q
    return (x3, y3, z3, t3)


def point_double(p):
    x1, y1, z1, t1 = p
    a = (x1 * x1) % Q
    b = (y1 * y1) % Q
    c = (2 * z1 * z1) % Q
    d = (-a) % Q
    e = ((x1 + y1) * (x1 + y1) - a - b) % Q
    g = (d + b) % Q
    f = (g - c) % Q
    h = (d - b) % Q
    x3 = (e * f) % Q
    y3 = (g * h) % Q
    z3 = (f * g) % Q
    t3 = (e * h) % Q
    return (x3, y3, z3, t3)


def scalarmult(p, e):
    e = e % L
    q = IDENTITY
    for i in range(255, -1, -1):
        q = point_double(q)
        if (e >> i) & 1:
            q = point_add(q, p)
    return q


def decode_point(enc):
    if len(enc) != 32:
        return None
    sign = (enc[31] >> 7) & 1
    y = int.from_bytes(enc, "little") % (1 << 255)
    if y >= Q:
        return None
    x = xrecover(y)
    if (x & 1) != sign:
        x = Q - x
    x2 = (x * x) % Q
    y2 = (y * y) % Q
    lhs = (y2 - x2) % Q
    rhs = (1 + DVAL * x2 % Q * y2) % Q
    if lhs != rhs:
        return None
    return (x, y, 1, (x * y) % Q)


def encode_point(p):
    x, y, z, t = p
    iz = _inv(z)
    x = (x * iz) % Q
    y = (y * iz) % Q
    bit = x & 1
    out = (y | (bit << 255)).to_bytes(32, "little")
    return out


def verify(pubkey, msg, sig):
    if len(pubkey) != 32:
        return False
    if len(sig) != 64:
        return False
    r_enc = sig[:32]
    s = int.from_bytes(sig[32:], "little")
    if s >= L:
        return False
    a_pt = decode_point(pubkey)
    if a_pt is None:
        return False
    r_pt = decode_point(r_enc)
    if r_pt is None:
        return False
    h = hashlib.sha512(r_enc + pubkey + msg).digest()
    h_int = int.from_bytes(h, "little") % L
    sb = scalarmult(BASE, s)
    ha = scalarmult(a_pt, h_int)
    rha = point_add(r_pt, ha)
    sb_enc = encode_point(sb)
    rha_enc = encode_point(rha)
    return sb_enc == rha_enc


def _clamp(raw32):
    b = bytearray(raw32)
    b[0] &= 0xF8
    b[31] &= 0x7F
    b[31] |= 0x40
    return int.from_bytes(b, "little")


def pubkey_from_seed(seed):
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    h = hashlib.sha512(seed).digest()
    a = _clamp(h[:32])
    pt = scalarmult(BASE, a)
    return encode_point(pt)


def sign(seed, msg):
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    h = hashlib.sha512(seed).digest()
    a = _clamp(h[:32])
    prefix = h[32:]
    r = int.from_bytes(hashlib.sha512(prefix + msg).digest(), "little") % L
    r_pt = scalarmult(BASE, r)
    r_enc = encode_point(r_pt)
    a_enc = encode_point(scalarmult(BASE, a))
    hram = int.from_bytes(hashlib.sha512(r_enc + a_enc + msg).digest(), "little") % L
    s = (r + hram * a) % L
    return r_enc + s.to_bytes(32, "little")
