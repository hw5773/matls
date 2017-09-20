import os
import sys
import time
import random

hash_lst = ["md5", "sha1", "sha224", "sha256", "ripemd160"]
out = {}

def usage():
    print ("Get contents from each domain")
    print ("python3 contents.py <top domains>")
    exit(1)

def get_contents(f):
    for line in f:
        tmp = line.strip().split(",")
        num = int(tmp[0].strip())
        dom = "www." + tmp[1].strip()
        cmd = "wget --no-clobber --convert-links --random-wait -p -E -e robots=off -U mozilla -P %s %s" % (num, dom)
        print ("%s) %s" % (num, dom))
        try:
            os.system(cmd)
        except:
            continue

        r = random.uniform(0, 5)
        time.sleep(r)



def main():
    if len(sys.argv) != 2:
        usage()

    f = open(sys.argv[1], "r")
    
    get_contents(f)

    f.close()

if __name__ == "__main__":
    main()
