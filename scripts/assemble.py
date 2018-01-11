import sys
import os

MAX_NUM = 798441

def usage():
	print ("Assemble the files")
	print ("python assemble.py <out file> <number>")
	exit(1)

def main():
	if len(sys.argv) != 2:
		usage()

	of = open(sys.argv[1], "w")
	end = int(sys.argv[2])
	err = open("err.log", "w")
	retry = open("retry.log", "w")

	if end == 0:
		end = MAX_NUM

	lst = []

	for root, dirs, files in os.walk("."):
		for f in files:
			if ".out" in f:
				lst.append(f)

	lst.sort()

	num = 0

	for e in lst:
		f = open(e, "r")
		for line in f:
			num = num + 1
			tmp = line.strip().split(",")
			n = int(tmp[0])

			if num > n:
				continue
			elif num == n:
				of.write(line)
			else num < n:
				while num < n:
					err_msg = "%d, error\n" % num
					of.write(err_msg)
					err.write(err_msg)
					num = num + 1

			if "file" in tmp[0]:
				retry_msg = "%d, retry\n" % num
				retry.write(retry_msg)

	of.close()
	err.close()

if __name__ == "__main__":
	main()
