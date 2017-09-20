import os
import sys
import hashlib

hash_lst = ["md5", "sha1", "sha224", "sha256", "ripemd160"]
out = {}

def usage():
	print ("python3 analyze.py")
	exit(1)

def assemble():
	for h in hash_lst:
		out[h] = []

	for root, dirs, files in os.walk("./"):
		for f in files:
			if "index_" in f:
				for h in hash_lst:
					if h in f:
						start = int(f.split("_")[2])
						out[h].append((start, f))

	for h in hash_lst:
		analysis(h)

def analysis(h):
	lst = sorted(out[h], key=lambda x:x[0])
	print (h, "(",len(lst), "): ", lst)
	fname = h + ".csv"
	of = open(fname, "w")
	of.write("num, size, hash\n")

	num = 0
	for e in lst:
		f = open(e[1], "r")
		f.readline()

		for line in f:
			tmp = line.strip().split(",")
			size = int(tmp[1])
			hvalue = tmp[2]
			s = hashlib.new(h).digest_size

			if size == 0:
				continue
			elif len(hvalue) != (s * 2) + 1:
				continue

			num = num + 1
			of.write(line)

	print (h, " total: ", num)

def main():
	if len(sys.argv) != 1:
		usage()

	assemble()

if __name__ == "__main__":
	main()	
