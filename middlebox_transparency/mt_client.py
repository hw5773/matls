import OpenSSL.crypto
import http.client
import sys
import json

def usage():
    print ("Middlebox Transparency Client")
    print ("Usage: python3 mt_client.py <mt log server IP> <mt log server port> <leaf certificate (PEM)> <root certificate (PEM)>")
    exit(1)

def get_cert_in_pem(fname):
    start = "-----BEGIN CERTIFICATE-----\n"
    end = "\n-----END CERTIFICATE-----\n"
    c = OpenSSL.crypto
    cert = c.load_certificate(c.FILETYPE_PEM, open(fname).read())
    dump = c.dump_certificate(c.FILETYPE_PEM, cert).decode()

    return dump[len(start):dump.index(end)].replace("\n", "")

def get_signed_certificate_timestamp(server, port, lfname, rfname):
    conn = http.client.HTTPConnection(server, port)
    leaf = get_cert_in_pem(lfname)
    root = get_cert_in_pem(rfname)

    js = '{"chain": ["%s","%s"]}' % (leaf, root)
    inputs = json.loads(js)
    headers = {"Content-type":"application/json"}

    conn.request("POST", "/ct/v1/add-chain", js, headers)

    response = conn.getresponse()
    print (response.read().decode())

def main():
    if len(sys.argv) != 5:
        usage()

    mt_server = sys.argv[1]
    mt_server_port = int(sys.argv[2])
    leaf_fname = sys.argv[3]
    root_fname = sys.argv[4]
    
    sct = get_signed_certificate_timestamp(mt_server, mt_server_port, leaf_fname, root_fname)

if __name__ == "__main__":
    main()
