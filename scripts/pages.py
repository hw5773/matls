import os
import sys
import json

def usage():
	print ("python3 pages.py <input file>")
	exit(1)

def main():
	if len(sys.argv) != 2:
		usage()

	f = open(sys.argv[1], "r")

	for line in f:
		js = json.loads(line)
		print ("Domains: ", js['domain'], " IP: ", js['ip'])

if __name__ == "__main__":
	main()
