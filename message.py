import base64
from typing import OrderedDict, Tuple, Union

from attribute import (
    Attribute,
    AttributeType,
    AutnAttribute,
    decode_attribute,
    MacAttribute,
    RandAttribute,
    ResAttribute,
)

from header import AKAHeader, EAPHeader, MessageCode, MessageType, MessageSubtype

from validator import AttributeValidator
from error import MacError


attribute_validator = AttributeValidator()


class AKAMessage:
    def __init__(self, eap_header: EAPHeader, aka_header: AKAHeader):
        self.eap_header = eap_header
        self.aka_header = aka_header
        self.attributes = OrderedDict()

    @classmethod
    def b64decode(cls, data: str):
        decoded = base64.b64decode(data)
        return cls.decode(decoded)

    @classmethod
    def decode(cls, data: bytes):
        eap_header = EAPHeader.decode(data)
        aka_header = AKAHeader.decode(data[4:8])

        message = AKAMessage(eap_header, aka_header)

        remainder = data[8:]
        while len(remainder) > 0:
            length = int(remainder[1]) * 4
            attr = decode_attribute(remainder[:length])
            message.add_attribute(attr)
            remainder = remainder[length:]

        return message

    @classmethod
    def challenge_request(cls, identifier: int, autn: bytes, rand: bytes):
        """
        Constructor for EAP-Request/AKA-Challenge with required attributes only.

        Required attributes: AT_AUTN and AT_RAND
        """
        eap_header = EAPHeader(MessageCode.Request, identifier, 0)
        aka_header = AKAHeader(MessageType.EapAka, MessageSubtype.AKAChallenge)

        message = AKAMessage(eap_header, aka_header)
        message.add_attribute(AutnAttribute(autn))
        message.add_attribute(RandAttribute(rand))
        message.add_attribute(MacAttribute())

        return message

    @classmethod
    def b64_hex_challenge_request(cls, identifier: int, autn_b64_hex: str, rand_b64_hex: str):
        """
        Constructor for EAP-Request/AKA-Challenge with required attributes only.

        Required attributes: AT_AUTN and AT_RAND
        """

        autn = bytearray.fromhex(base64.b64decode(autn_b64_hex.encode()).decode())
        rand = bytearray.fromhex(base64.b64decode(rand_b64_hex.encode()).decode())

        eap_header = EAPHeader(MessageCode.Request, identifier, 0)
        aka_header = AKAHeader(MessageType.EapAka, MessageSubtype.AKAChallenge)

        message = AKAMessage(eap_header, aka_header)
        message.add_attribute(AutnAttribute(autn))
        message.add_attribute(RandAttribute(rand))
        message.add_attribute(MacAttribute())

        return message

    @classmethod
    def challenge_response(cls, identifier: int, res: bytes):
        """
        Constructor for EAP-Response/AKA-Challenge with required attributes only.

        Required attributes: AT_RES
        """
        eap_header = EAPHeader(MessageCode.Response, identifier, 0)
        aka_header = AKAHeader(MessageType.EapAka, MessageSubtype.AKAChallenge)

        message = AKAMessage(eap_header, aka_header)
        message.add_attribute(ResAttribute(res))
        message.add_attribute(MacAttribute())

        return message

    def validate(self, key: Union[bytes, None] = None):
        """
        validate message.

        If key is provided and AT_MAC is an attribute, the message's MAC is validated

        raises:
            ValidationError if message is invalid
        """

        attribute_validator.validate(self.eap_header.code, self.aka_header.message_subtype, self.attributes)

        if AttributeType.AT_MAC in self.attributes and key is not None:
            attr: MacAttribute = self.attributes[AttributeType.AT_MAC]
            mac = attr.mac

            encoding, _ = self.premac_encode()

            attr.sign(key, encoding)

            if attr.mac != mac:
                # Replace original mac value
                error = MacError(mac, attr.mac)
                attr.mac = mac
                raise error

    def add_attribute(self, attribute: Attribute):
        """
        Add attribute to message
        """
        self.attributes[attribute.attribute_type] = attribute

        # Both eap_header and aka_header are of length 4 bytes
        length = 4 + 4
        for attribute in self.attributes.values():
            length += attribute.byte_count

        # Update the eap_header's length when adding a new attribute
        self.eap_header.length = length

    def premac_encode(self) -> Tuple[bytes, int]:
        """
        Encode message with MAC attribute set to 0.

        Used for encoding message to use with MAC generation
        """
        encoding = self.eap_header.encode() + self.aka_header.encode()

        mac_index = 0
        for attr in self.attributes.values():
            if attr.attribute_type == AttributeType.AT_MAC:
                attr.clear()
                mac_index = len(encoding)
            encoding += attr.encode()

        return encoding, mac_index

    def postmac_encode(self) -> bytes:
        """
        Encode message when MAC has already been set
        """
        encoding = self.eap_header.encode() + self.aka_header.encode()

        for attr in self.attributes.values():
            encoding += attr.encode()

        return encoding

    def encode(self, key: Union[bytes, None] = None) -> bytes:
        """
        Encode message and sign with MAC if key is provided
        """

        mac_calculation_required = (
            AttributeType.AT_MAC in self.attributes and not self.attributes[AttributeType.AT_MAC].is_set()
        )

        # if mac_calculation_required and key is None:
        #     raise Exception("AT_MAC requires key for generating MAC value")

        # Calculate the message MAC if key is provided
        if mac_calculation_required and key is not None:
            encoding, mac_index = self.premac_encode()

            mac: MacAttribute = self.attributes[AttributeType.AT_MAC]
            mac.sign(key, encoding)

            mac_bytes = mac.encode()
            encoding = encoding[:mac_index] + mac_bytes + encoding[mac_index + len(mac_bytes) :]
        else:
            encoding = self.postmac_encode()

        return encoding

    def b64encode(self, key: Union[bytes, None] = None) -> bytes:
        """
        Encode message in base64 format
        """
        encoded = self.encode(key)
        return base64.b64encode(encoded)

    def __eq__(self, other) -> bool:
        return (
            self.eap_header == other.eap_header
            and self.aka_header == other.aka_header
            and self.attributes == other.attributes
        )

    def __str__(self) -> str:
        result = self.eap_header.__str__() + "\n  "
        result += self.aka_header.__str__()
        for attr in self.attributes.values():
            result += "\n    " + attr.__str__()
        return result

    def verbose_str(self) -> str:
        result = self.eap_header.__str__() + "\n  "
        result += self.aka_header.__str__()
        for attr in self.attributes.values():
            result += "\n    " + attr.verbose_str()
        return result
