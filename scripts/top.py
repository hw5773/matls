from bs4 import BeautifulSoup
import os
import urllib.request
import sys

def usage():
    print ("Purpose: Crawling Top 1,000,000 sites from stuffgate.")
    print ("Usage: python3 top.py <output file name>")
    exit(1)

def crawler(out):
    num = 0

    for i in range(1, 1001):
        req = "http://stuffgate.com/stuff/website/top-%s-sites" % str(i * 1000)

        with urllib.request.urlopen(req) as f:
            doc = f.read()
            soup = BeautifulSoup(doc, 'html.parser')
            lst = soup.find_all('a')

            for e in lst:
                if e.get("target"):
                    num = num + 1
                    out.write(str(num) + ", " + e.get('href')[7:] + "\n")

            print ("total: ", num)

def main():
    if len(sys.argv) != 2:
        usage()
    out = open(sys.argv[1], "w")
    crawler(out)

if __name__ == "__main__":
    main()

