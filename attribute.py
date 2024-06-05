import hashlib
import hmac
from dataclasses import dataclass
from enum import Enum
from typing import Union

import ordering


class AttributeType(Enum):
    UNKNOWN = 0
    AT_RAND = 1
    AT_AUTN = 2
    AT_RES = 3
    AT_AUTS = 4
    AT_PADDING = 6
    AT_NONCE_MT = 7
    AT_PERMANENT_ID_REQ = 10
    AT_MAC = 11
    AT_NOTIFICATION = 12
    AT_ANY_ID_REQ = 13
    AT_IDENTITY = 14
    AT_VERSION_LIST = 15
    AT_SELECTED_VERSION = 16
    AT_FULLAUTH_ID_REQ = 17
    AT_COUNTER = 19
    AT_COUNTER_TOO_SMALL = 20
    AT_NONCE_S = 21
    AT_CLIENT_ERROR_CODE = 22
    AT_IV = 129
    AT_ENCR_DATA = 130
    AT_NEXT_PSEUDONYM = 132
    AT_NEXT_REAUTH_ID = 133
    AT_CHECKCODE = 134
    AT_RESULT_IND = 135


@dataclass
class Attribute:
    """
     Attribute Type

          Indicates the particular type of attribute.  The attribute type
          values are listed in Section 11.

    Length

          Indicates the length of this attribute in multiples of 4 bytes.
          The maximum length of an attribute is 1024 bytes.  The length
          includes the Attribute Type and Length bytes.

    Value

          The particular data associated with this attribute.  This field
          is always included and it is two or more bytes in length.  The
          type and length fields determine the format and length of the
          value field.
    """

    _attribute_code: int
    _attribute_type: AttributeType
    length: int
    value: bytes
    raw: bytes

    def __init__(
        self,
        code: Union[AttributeType, int],
        value: bytes,
        raw: Union[bytes, None] = None,
    ):
        if type(code) == AttributeType:
            self._attribute_code = code.value
            self._attribute_type = code
        else:
            self._attribute_code = code
            try:
                self._attribute_type = AttributeType(code)
            except ValueError:
                self._attribute_type = AttributeType.UNKNOWN

        self.length = int((len(value) + 2) / 4)
        self.value = value

        if raw is None:
            raw = self.encode()
        self.raw = raw

    def encode(self) -> bytes:
        """
         0                   1                   2                   3
         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |Attribute Type |    Length     | Value...
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        """
        return self.attribute_type.value.to_bytes(1, ordering.BIG) + self.length.to_bytes(1, ordering.BIG) + self.value

    @property
    def byte_count(self) -> int:
        return len(self.value) + 2

    @property
    def attribute_code(self) -> int:
        return self._attribute_code

    @property
    def attribute_type(self) -> AttributeType:
        return self._attribute_type

    @attribute_code.setter
    def attribute_code(self, value: int):
        self._attribute_code = value
        try:
            self._attribute_type = AttributeType(value)
        except ValueError:
            self._attribute_type = AttributeType.UNKNOWN

    @attribute_type.setter
    def attribute_type(self, value: AttributeType):
        self._attribute_code = value.value
        self._attribute_type = value

    @classmethod
    def decode(cls, payload: bytes):
        attribute_code = int(payload[0])
        length = int(payload[1]) * 4
        offset = 2
        value = payload[offset : offset + length]
        return Attribute(attribute_code, value, raw=payload)

    def __str__(self) -> str:
        return (
            f"{self.__class__.__name__}(type={self._attribute_type.name}, "
            f"code={self._attribute_code}, length={self.length}, value={self.value.hex()})"
        )

    def verbose_str(self) -> str:
        return (
            f"{self.__class__.__name__}(type={self._attribute_type.name}, "
            f"code={self._attribute_code}, length={self.length}, value={self.value.hex()}, bytes={self.raw.hex()})"
        )


@dataclass
class RandAttribute(Attribute):
    """
    AT_RAND: https://datatracker.ietf.org/doc/html/rfc4187#section-10.6

    rand: 16 bytes (128 bits)
    """

    rand: bytes

    def __init__(self, rand: bytes):
        value = b"\0" * 2 + rand
        super().__init__(AttributeType.AT_RAND, value)
        self.rand = rand


@dataclass
class AutnAttribute(Attribute):
    """
    AT_AUTN: https://datatracker.ietf.org/doc/html/rfc4187#section-10.7

    autn: 16 bytes (128 bits)
    """

    autn: bytes

    def __init__(self, autn: bytes):
        value = b"\0" * 2 + autn
        super().__init__(AttributeType.AT_AUTN, value)
        self.autn = autn


@dataclass
class ResAttribute(Attribute):
    """
    AT_RES: https://datatracker.ietf.org/doc/html/rfc4187#section-10.8

    res_length: exact length of res in bits
    res: can vary between 32 and 128 bits and must be a multiple of 4 bytes
    """

    res_length: int
    res: bytes

    def __init__(self, res: bytes):
        res_length = len(res) * 8
        value = res_length.to_bytes(2, ordering.BIG) + res
        super().__init__(AttributeType.AT_RES, value)
        self.res_length = res_length
        self.res = res


@dataclass
class MacAttribute(Attribute):
    """
    AT_MAC: https://datatracker.ietf.org/doc/html/rfc4187#section-10.15

    mac: 16 bytes (128 bits)
    """

    _mac: bytes

    def __init__(self, mac: bytes = b"\0" * 16):
        value = b"\0" * 2 + mac  # 2 reserved bytes + 16 bytes for MAC
        super().__init__(AttributeType.AT_MAC, value)
        self._mac = mac

    def sign(self, key: bytes, message: bytes):
        digester = hmac.new(key, message, hashlib.sha1)
        signature = digester.digest()
        self.mac = signature[:16]
        self.raw = self.encode()

    @property
    def mac(self) -> bytes:
        return self._mac

    def is_set(self) -> bool:
        return self._mac != b"\0" * 16

    @mac.setter
    def mac(self, val: bytes):
        self._mac = val
        self.value = b"\0" * 2 + val

    def clear(self):
        self.mac = b"\0" * 16


def decode_attribute(payload: bytes):
    attribute = Attribute.decode(payload)

    if attribute.attribute_type == AttributeType.AT_RAND:
        attribute.__class__ = RandAttribute
        attribute.rand = attribute.value[2:]
    elif attribute.attribute_type == AttributeType.AT_AUTN:
        attribute.__class__ = AutnAttribute
        attribute.autn = attribute.value[2:]
    elif attribute.attribute_type == AttributeType.AT_RES:
        attribute.__class__ = ResAttribute
        attribute.res_length = int.from_bytes(attribute.value[0:2], ordering.BIG)
        attribute.res = attribute.value[2:]
    elif attribute.attribute_type == AttributeType.AT_MAC:
        attribute.__class__ = MacAttribute
        attribute.mac = attribute.value[2:]

    return attribute
