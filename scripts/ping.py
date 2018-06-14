from etc import domains
import os
import sys

def usage():
    print ("python3 ping.py <domains> <output file>")
    exit(1)

def ping_measure(lst, of):
    f = open(of, "w")
    num = 0

    for e in lst:
        e = "www." + e.replace("_", ".")
        p = os.popen("timeout 30 ping -c 10 %s" % e).read()
        result = p.split("=")[-1].strip().split(" ")[0].split("/")
        num = num + 1
        s = str(num) + "," + e + "," + ','.join(result)
        print ("s: ", s)
        f.write(s + "\n")

    f.close()

def main():
    if len(sys.argv) != 3:
        usage()

    lst = domains(sys.argv[1])
    of = sys.argv[2]
    ping_measure(lst, of)

if __name__ == "__main__":
    main()
