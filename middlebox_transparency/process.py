import OpenSSL.crypto
import os, hashlib, time
from flask import json, jsonify

SUCCESS = 1
FAILURE = -1

VERSION_V1 = 0

# The process module of the middlebox transparency log server
class Process:
    def post_certchain(self, chain):
        start = "-----BEGIN CERTIFICATE-----\n"
        end = "\n-----END CERTIFICATE-----\n"
        cert = "%s%s%s" % (start, chain[2:chain.index(",")-1], end)

        c = OpenSSL.crypto
        leaf = c.load_certificate(c.FILETYPE_PEM, cert)
        pk = c.dump_publickey(c.FILETYPE_ASN1, leaf.get_pubkey())

        h = hashlib.sha256()
        h.update(pk)
        log_id = h.hexdigest()

        js = { "sct_version": VERSION_V1,
                "id": log_id,
                "timestamp": int(time.time() * 1000),
                "extensions": "" }

        print (json.dumps(js))

