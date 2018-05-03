import os
import sys

def usage():
    print ("Get contents from each domain")
    print ("python3 contents.py <top domains> <result file>")
    exit(1)

def get_index_file(dname, dom):


def get_contents(dname, cdname, dom):
    


    return n

def content(f, of):
    num = 0
    for line in f:
        num = num + 1
        dname = line.strip().replace(", ", "_")
        dom = dname.split("_")[-1]
        cdname = dname + "/contents"
        print ("dname: ", dname)
        os.mkdir(dname)
        os.mkdir(cdname)
        get_index_file(dname, dom)
        n = get_contents(dname, cdname, dom) # n: # of contents + index.html
        s = str(num) + ", " + str(n) + "\n"
        of.write(s)

def main():
    if len(sys.argv) != 3:
        usage()

    f = open(sys.argv[1], "r")
    of = open(sys.argv[2], "w")

    content(f, of)

    f.close()
    of.close()

if __name__ == "__main__":
    main()
