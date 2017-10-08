import sys

def usage():
	print ("Search the keyword in the document.")
	print ("python3 search_key.py <input file> <key>")
	exit(1)

def main():
	if len(sys.argv) != 3:
		usage()

	try:
		f = open(sys.argv[1], "r")
		key = sys.argv[2]

		tmp1 = f.read()
		tmp2 = tmp1.split("\n")

		print ("lines: ", len(tmp2))

		for e in tmp2:
			if key in e:
				print (e)

		f.close()
	except:
		print ("No Such File: %s" % sys.argv[1])
		print ("Please try again.")

if __name__ == "__main__":
	main()
