# EAP-AKA Encoder / Decoder

Working EAP-AKA example

## Encoding file format

### EAP-AKA Request Attributes

- `"autn"`
- `"rand"`

### EAP-AKA Response Attributes

- `"res"`

### MAC Signing Attributes

- `"username"`
- `"ck"`
- `"ik"`

In summary, `"autn"` and `"rand"` are required to generate the EAP-AKA Request message. `"res"` is required to generate the EAP-AKA Response message.

### Option 1: `"username"`, `"ck"`, and `"ik"` attributes used for generating signing key `"k_aut"`

```json
{
    "identifier": 0,
    "username": "310990000047144",
    "rand": <base64_encoded_rand_bytes>,
    "res": <base64_encoded_res_bytes>,
    "autn": <base64_encoded_autn_bytes>,
    "ck": <base64_encoded_ck_bytes>,
    "ik": <base64_encoded_ik_bytes>
}
```

### Option 2: `"k_aut"` signing key

```json
{
    "identifier": 0,
    "rand": <base64_encoded_rand_bytes>,
    "res": <base64_encoded_res_bytes>,
    "autn": <base64_encoded_autn_bytes>,
    "k_aut": <base64_encoded_ck_bytes>
}
```

## Encoding

```shell
./encode.py data.json
```

## Decoding

```shell
# Decode without MAC validation
./decode.py <base64_encoded_eapaka_message>

# Decode with MAC validation
./decode.py <base64_encoded_eapaka_message> -k <base64_encoded_kaut>
```

## Dependencies

- Python 3
