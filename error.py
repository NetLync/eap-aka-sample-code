from typing import List

from attribute import AttributeType


class ValidationError(Exception):
    def __init__(self, required: List[AttributeType] = [], disallowed: List[AttributeType] = []):
        self.required = required
        self.disallowed = disallowed

    def __eq__(self, other) -> bool:
        return self.required == other.required and self.disallowed == other.disallowed


class MacError(Exception):
    def __init__(self, expected: bytes, actual: bytes):
        self.expected = expected
        self.actual = actual

    def __eq__(self, other) -> bool:
        return self.expected == other.expected and self.actual == other.actual
