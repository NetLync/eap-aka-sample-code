import base64
from hashlib import sha1
from typing import List, Tuple

import ordering
from hash import sha1_block


def master_key(identity: bytes, ik: bytes, ck: bytes) -> bytes:
    """
    master_key: MK = SHA1(Identity|IK|CK) from RFC 4187, Section 7 
    """
    m = sha1()
    m.update(identity)
    m.update(ik)
    m.update(ck)
    return m.digest()


def x_func(x_key: bytes) -> bytes:
    """
    x_func: Pseudo-Random Number Generator from RFC 4187, Appendix A
    """
    x_val = bytes()

    for _ in range(4):
        h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
        w0 = g_func(h, x_key)
        x_val = x_val + w0
        x_key = update_x_key(x_key, w0)
        w1 = g_func(h, x_key)
        x_val = x_val + w1
        x_key = update_x_key(x_key, w1)

    if len(x_val) != 160:
        raise Exception(len(x_val))

    return x_val


def g_func(h: List[int], data: bytes) -> bytes:
    """
    g_func: FIPS 186-2 G function
    FIPS Publication 186-2 (with Change Notice 1) Section 3.3
    """
    bh = sha1_block(h, data)

    digest = bytes()
    for b in bh:
        digest += b.to_bytes(4, byteorder=ordering.BIG, signed=False)
    return digest


def update_x_key(x_key: bytes, w: bytes) -> bytes:
    """
    update_x_key: x_key = (1 + x_key + w_i) % 2^160
    """
    xki = 1 + int.from_bytes(x_key, ordering.BIG)
    xki += int.from_bytes(w, ordering.BIG)

    x = xki.to_bytes(100, byteorder=ordering.BIG)
    l = len(x)
    if l > 20:
        x = x[l - 20 :]
    elif l < 20:
        x = "x\00" * (20 - l) + x

    return x


def make_aka_keys(identity: bytes, ik: bytes, ck: bytes) -> Tuple[bytes, bytes, bytes, bytes]:
    """
    make_aka_keys

    Args:
        identity: carrier server host name
        ik: 16-byte integrity check (IK)
        ck: 16-byte cipher key (CK)

    Returns:
        K_ENCR: encryption key
        K_AUT: authentication key
        MSK: master session key
        EMSK: extended master session key
    """
    mk = master_key(identity, ik, ck)
    x = x_func(mk)
    return x[:16], x[16:32], x[32:96], x[96:160]


def make_aka_keys_b64(identity_b64: str, ik_b64_hex: str, ck_b64_hex: str) -> Tuple[bytes, bytes, bytes, bytes]:
    """
    make_aka_keys_b64

    Args:
        identity_b64: base64 encoded carrier server host name
        ik_b64_hex: base64 encoded integrity check (IK) hex string
        ck_b64_hex: base64 encoded cipher key (CK) hex string

    Returns:
        K_ENCR: encryption key
        K_AUT: authentication key
        MSK: master session key
        EMSK: extended master session key
    """
    # TODO:
    # Currently, base64 decoded subscriber-id is left padded
    # with the byte string b"\x02\x00\x00;\x01"
    # Possibly remove this left-trim or replace with
    # a regex for the carrier's Username template.
    identity = base64.b64decode(identity_b64.encode())
    if identity.startswith(b"\x02\x00\x00;\x01"):
        identity = identity[5:]
    ik = bytearray.fromhex(base64.b64decode(ik_b64_hex.encode()).decode())
    ck = bytearray.fromhex(base64.b64decode(ck_b64_hex.encode()).decode())
    mk = master_key(identity, ik, ck)
    x = x(mk)
    return x[:16], x[16:32], x[32:96], x[96:160]
