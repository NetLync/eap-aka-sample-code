from dataclasses import dataclass
from enum import Enum

import ordering


class MessageCode(Enum):
    """
    The Code field is one octet and identifies the Type of EAP packet.
    EAP Codes are assigned as follows:

        1       Request
        2       Response
        3       Success
        4       Failure
    """

    Request = 1
    Response = 2
    Success = 3
    Failure = 4


class MessageType(Enum):
    EapAka = 23


class MessageSubtype(Enum):
    AKAChallenge = 1
    AKAAuthenticationReject = 2
    AKASynchronizationFailure = 4
    AKAIdentity = 5
    SIMStart = 10
    SIMChallenge = 11
    AKANotification = 12  # and SIM-Notification
    AKAReauthentication = 13  # and SIM-Reauthentication
    AKAClientError = 14  # and SIM-Client-Error


@dataclass
class EAPHeader:
    """
     A summary of the EAP packet format is shown below.  The fields are
    transmitted from left to right.

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Code      |  Identifier   |            Length             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |    Data ...
    +-+-+-+-+

    Code

       The Code field is one octet and identifies the Type of EAP packet.
       EAP Codes are assigned as follows:

          1       Request
          2       Response
          3       Success
          4       Failure

       Since EAP only defines Codes 1-4, EAP packets with other codes
       MUST be silently discarded by both authenticators and peers.

    Identifier

       The Identifier field is one octet and aids in matching Responses
       with Requests.

    Length

       The Length field is two octets and indicates the length, in
       octets, of the EAP packet including the Code, Identifier, Length,
       and Data fields.  Octets outside the range of the Length field
       should be treated as Data Link Layer padding and MUST be ignored
       upon reception.  A message with the Length field set to a value
       larger than the number of received octets MUST be silently
       discarded.

    Data

       The Data field is zero or more octets.  The format of the Data
       field is determined by the Code field.
    """

    code: MessageCode
    identifier: int
    length: int

    def __init__(self, code, identifier, length):
        self.code = code
        self.identifier = identifier
        self.length = length

    def encode(self) -> bytes:
        """
         0                   1                   2                   3
         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |     Code      |  Identifier   |            Length             |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        """
        return (
            self.code.value.to_bytes(1, ordering.BIG)
            + self.identifier.to_bytes(1, ordering.BIG)
            + self.length.to_bytes(2, ordering.BIG)
        )

    @classmethod
    def decode(cls, payload: bytes):
        code = MessageCode(int(payload[0]))
        identifier = int(payload[1])
        length = int.from_bytes(payload[2:4], ordering.BIG)
        return EAPHeader(code, identifier, length)

    def __str__(self) -> str:
        return f"{self.__class__.__name__}(code={self.code.name}, identifier={self.identifier}, length={self.length})"


@dataclass
class AKAHeader:
    message_type: MessageType
    message_subtype: MessageSubtype

    def encode(self) -> bytes:
        """
         0                   1                   2                   3
         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |     Type      |    Subtype    |           Reserved            |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        """
        return (
            self.message_type.value.to_bytes(1, ordering.BIG)
            + self.message_subtype.value.to_bytes(1, ordering.BIG)
            + int(0).to_bytes(2, ordering.BIG)
        )

    @classmethod
    def decode(cls, payload: bytes):
        message_type = MessageType(int(payload[0]))
        message_subtype = MessageSubtype(int(payload[1]))
        return AKAHeader(message_type, message_subtype)

    def __str__(self) -> str:
        return f"{self.__class__.__name__}(type={self.message_type.name}, subtype={self.message_subtype.name})"
