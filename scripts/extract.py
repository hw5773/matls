import sys

def usage():
    print ("Extract domains which are not fetched")
    print ("python3 extract.py <input file> <output file>")
    exit(1)

def main():
    if len(sys.argv) != 3:
        usage()

    f = open(sys.argv[1], "r")
    of = open(sys.argv[2], "w")

    for line in f:
        if "no file" in line:
            num = int(line.strip().split(",")[0])
            s = "%d\n" % num
            of.write(s)

if __name__ == "__main__":
    main()
