#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import json
import base64
from pyasn1.codec.ber import decoder


def main():
    if len(sys.argv) < 3:
        print("usage: cs_data.py input.json output.json")
        return

    decoder.decode.defaultErrorState = decoder.stDumpRawValue

    with open(sys.argv[1]) as f:
        data = json.load(f)

    cs = data[0]['certificate_sign']
    p7s = base64.b64decode(cs)
    asn = decoder.decode(p7s)
    raw = str(asn[0][1][2][1])

    with open(sys.argv[2], 'w') as f:
        f.write(raw)


if __name__ == '__main__':
    main()

