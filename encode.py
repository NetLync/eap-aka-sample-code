#! /usr/bin/env python3

import argparse
import base64
import json

from message import AKAMessage
from keys import make_aka_keys


def cli(file: str, verbose: bool):
    def info(x):
        return print(x) if verbose else None

    try:
        with open(file, "r") as f:
            data = json.loads(f.read())
    except Exception as e:
        print(e)
        return

    result = {}

    identifier = data.get("identifier", 0)

    if "k_aut" in data:
        k_aut = base64.b64decode(data["k_aut"].encode())
        result["k_aut"] = data["k_aut"]
    elif "username" in data and "ik" in data and "ck" in data:
        username = data["username"].encode()
        ik = base64.b64decode(data["ik"].encode())
        ck = base64.b64decode(data["ck"].encode())
        _, k_aut, _, _ = make_aka_keys(username, ik, ck)
        result["k_aut"] = base64.b64encode(k_aut).decode()
    else:
        info("Skipping MAC signing since attributes not provided...")
        k_aut = None

    if "autn" in data and "rand" in data:
        info("Generating EAP-AKA Request...")

        autn = base64.b64decode(data["autn"].encode())
        rand = base64.b64decode(data["rand"].encode())

        message = AKAMessage.challenge_request(identifier, autn, rand)
        request = message.b64encode(k_aut).decode()
        result["challenge"] = request

    if "res" in data:
        info("Generating EAP-AKA Response...")
        res = base64.b64decode(data["res"].encode())
        message = AKAMessage.challenge_response(identifier, res)
        response = message.b64encode(k_aut).decode()
        result["expected_result"] = response

    print(json.dumps(result, indent=4))


if __name__ == "__main__":
    parser = argparse.ArgumentParser("Encode EAP-AKA attributes into EAP-AKA messages")
    parser.add_argument("file", help="path to attributes data file")
    parser.add_argument("-v", "--verbose", help="verbose mode", action="store_true")
    args = parser.parse_args()

    cli(args.file, args.verbose)
