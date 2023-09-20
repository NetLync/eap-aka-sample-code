#! /usr/bin/env python3

import argparse
import base64

from message import AKAMessage
from error import MacError, ValidationError


def cli(message: str, key: str, verbose: bool):
    decoded = AKAMessage.b64decode(message)
    if verbose:
        print(decoded.verbose_str())
    else:
        print(decoded)

    if key:
        key_bytes = base64.b64decode(key.encode())
        # print(key_bytes)
        try:
            decoded.validate(key_bytes)
            print("MAC successfully validated!")
        except (MacError, ValidationError):
            print("MAC cannot be validated")


if __name__ == "__main__":
    parser = argparse.ArgumentParser("Decode EAP-AKA messages")
    parser.add_argument("message", help="Base-64 encoded message")
    parser.add_argument("-k", "--key", help="MAC validation key")
    parser.add_argument("-v", "--verbose", help="verbose mode", action="store_true")
    args = parser.parse_args()

    cli(args.message, args.key, args.verbose)
