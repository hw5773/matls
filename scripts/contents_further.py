from bs4 import BeautifulSoup
import os
import sys
import hashlib

hash_lst = ["md5", "sha1", "sha224", "sha256", "ripemd160"]
out = {}

def usage():
    print ("Get contents from each domain")
    print ("python3 contents.py <top domains> <result file> <start number> <num of domains>")
    exit(1)

def store_hash(dname):
	index = dname + "/index"

	for lib in hash_lst:
		h = hashlib.new(lib)
		try:
			c = open(index, "rb")
		except:
			break
		try:
			h.update(c.read())
			hash_val = h.hexdigest()
		except:
			c.close()
		try:
			statinfo = os.stat(index)
		except:
			break
		size = statinfo.st_size
		s = "%s, %s, %s\n" % (num, size, hash_val)
		out[lib].write(s)

def get_index_file(dname, dom):
    path = dname + "/header"
    index = dname + "/index"
    num = int(dname.split("_")[0])
    cmd = "timeout 10 curl -A \"Mozilla/5.0\" -L -s -D %s \"www.%s\" > %s" % (path, dom, index)
    os.system(cmd)
	store_hash(dname)
    print ("  Get: ", index)

def make_index_hash(f, of, start, domains):
	num = 0
    for line in f:
        num = num + 1

        if num < start:
            continue
        elif num >= start + domains:
            break

        dname = line.strip().replace(", ", "_")
        dom = dname.split("_")[-1]
        cdname = dname + "/contents"
        print ("Domain Name: ", dname)
        try:
            os.mkdir(dname)
            os.mkdir(cdname)
        except:
			index = dname + "/index"
			statinfo = os.stat(index)
			if statinfo.st_size != 190:
				store_hash(dname)
				print ("Exist: ", dname)
            	continue
        get_index_file(dname, dom)
        s = str(num) + "\n"
        of.write(s)

def main():
    if len(sys.argv) != 5:
        usage()

    f = open(sys.argv[1], "r")
    of = open(sys.argv[2], "w")
    start = int(sys.argv[3])
    domains = int(sys.argv[4])
    
    for h in hash_lst:
        name = "index_%s_%s_%s.csv" % (h, start, start + domains - 1)
        out[h] = open(name, "w")
        out[h].write("num, size, hash\n")

    make_index_hash(f, of, start, domains)

    f.close()
    of.close()

    for h in hash_lst:
        out[h].close()

if __name__ == "__main__":
    main()
