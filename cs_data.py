#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import json
import base64
from pyasn1.codec.ber import decoder

def prec(root, level=0, path=""):
    if level > 5:
        return
    count = 0
    for r in root:
        p = path + "." + str(count)
        print("%d: [%s] %s %s" % (level, path, "    " * level, str(r)))
        try:
            prec(r, level+1, p)
        except:
            pass
        count += 1
        if count > 100:
            break

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

