import ctypes
import struct
from typing import List


H = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]


def rotate(n, b):
    """
    Left rotates n by b.
    """
    return ((n << b) | (n >> (32 - b))) & 0xFFFFFFFF


def padding(data):
    """
    Pads the input message with zeros so that padded_data has 64 bytes or 512 bits
    """
    padding_length = 0
    mod = len(data) % 64
    if mod != 0:
        padding_length = 64 - mod

    return data + b"\x00" * padding_length


def split_blocks(padded_data):
    """
    Returns a list of bytestrings each of length 64
    """
    return [padded_data[i : i + 64] for i in range(0, len(padded_data), 64)]


def shift32(n, b):
    """
    Shift left n by b.
    """
    return ctypes.c_uint32((n << b)).value


def expand_block(block):
    """
    Takes a bytestring-block of length 64, unpacks it to a list of integers and
    returns a list of 80 integers after some bit operations
    """
    w = list(struct.unpack(">16L", block)) + [0] * 64
    for i in range(0, 16):
        j = i * 4
        w[i] = shift32(block[j], 24) | shift32(block[j + 1], 16) | shift32(block[j + 2], 8) | block[j + 3]
    for i in range(16, 80):
        w[i] = rotate((w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]), 1)
    return w


def sha1_block(h: List[int], data: bytes) -> List[int]:
    """
    Calls all the other methods to process the input. Pads the data, then splits
    into blocks and then does a series of operations for each block (including
    expansion).
    For each block, the variable h that was initialized is copied to a,b,c,d,e
    and these 5 variables a,b,c,d,e undergo several changes. After all the blocks
    are processed, these 5 variables are pairwise added to h ie a to h[0], b to h[1]
    and so on.  This h becomes our final hash which is returned.
    """

    h0, h1, h2, h3, h4 = h[0], h[1], h[2], h[3], h[4]

    padded_data = padding(data)
    blocks = split_blocks(padded_data)
    for block in blocks:
        expanded_block = expand_block(block)
        a, b, c, d, e = h0, h1, h2, h3, h4
        for i in range(0, 80):
            if 0 <= i < 20:
                f = (b & c) | ((~b) & d)
                k = 0x5A827999
            elif 20 <= i < 40:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= i < 60:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            elif 60 <= i < 80:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            a, b, c, d, e = (
                rotate(a, 5) + f + e + k + expanded_block[i] & 0xFFFFFFFF,
                a,
                rotate(b, 30),
                c,
                d,
            )

        h0 += a
        h1 += b
        h2 += c
        h3 += d
        h4 += e

    return [
        ctypes.c_uint32(h0).value,
        ctypes.c_uint32(h1).value,
        ctypes.c_uint32(h2).value,
        ctypes.c_uint32(h3).value,
        ctypes.c_uint32(h4).value,
    ]
