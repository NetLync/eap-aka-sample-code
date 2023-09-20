from typing import Dict, List, OrderedDict

from attribute import Attribute, AttributeType
from header import MessageCode, MessageSubtype

from error import ValidationError


class AttributeRule:
    required: List[AttributeType]
    optional: List[AttributeType]

    def __init__(self, required: List[AttributeType], optional: List[AttributeType]):
        self.required = required
        self.optional = optional
        self.required_set = set(self.required)
        self.optional_set = set(self.optional)

    def validate(self, attributes: OrderedDict[AttributeType, Attribute]):
        attribute_types = set(attributes.keys())

        diff = self.required_set.difference(attribute_types)
        disallowed = attribute_types.difference(self.required_set).difference(self.optional_set)

        if len(diff) > 0 or len(disallowed) > 0:
            raise ValidationError(required=sorted(list(diff)), disallowed=sorted(list(disallowed)))


class AttributeValidator:
    def __init__(self):
        self.validators: Dict[(MessageCode, MessageSubtype), AttributeRule] = {
            (MessageCode.Request, MessageSubtype.AKAChallenge): AttributeRule(
                required=[
                    AttributeType.AT_AUTN,
                    AttributeType.AT_RAND,
                    AttributeType.AT_MAC,
                ],
                optional=[
                    AttributeType.AT_NEXT_PSEUDONYM,
                    AttributeType.AT_NEXT_REAUTH_ID,
                    AttributeType.AT_IV,
                    AttributeType.AT_ENCR_DATA,
                    AttributeType.AT_PADDING,
                    AttributeType.AT_CHECKCODE,
                    AttributeType.AT_RESULT_IND,
                ],
            ),
            (MessageCode.Response, MessageSubtype.AKAChallenge): AttributeRule(
                required=[AttributeType.AT_RES, AttributeType.AT_MAC],
                optional=[AttributeType.AT_CHECKCODE, AttributeType.AT_RESULT_IND],
            ),
        }

    def validate(
        self,
        message_code: MessageCode,
        message_subtype: MessageSubtype,
        attributes: OrderedDict[AttributeType, Attribute],
    ):
        validator = self.validators.get((message_code, message_subtype), None)

        if validator is not None:
            validator.validate(attributes)
