from bs4 import BeautifulSoup
import os
import sys
import subprocess
import json
import urllib.request
import time
from socket import gethostbyname

def usage():
    print ("Find the related domain for ipinfo.io")
    print ("python3 domain.py <input file name> <output file name> <start> <end>")
    exit(1)

def crawler(f, of, start, end):
    num = start
    for i in range(start-1):
        f.readline()

    for line in f:
        if num > end:
            break
        tmp = line.strip().split(",")
        domain = "www." + tmp[1].strip()
        print ("Domain: ", domain)
        try:
            ip = gethostbyname(domain)
        except:
            print ("DNS Error")
            of.write(str(num) + ", none, none, none\n")
            num = num + 1
            continue

        req = "https://ipinfo.io/%s" % ip
        os.system("timeout 3 wget " + req)
        
        try:
            g = open(ip, "r")
            output = g.read()
            js = json.loads(output)
            g.close()
            os.remove(ip)
        except:
            print ("File Not Found")
            of.write(str(num) + ", " + domain + ", none, none\n")
            num = num + 1
            continue

        dom = ""

        if "org" in js.keys():
            asn = js["org"].split(" ")[0]
            as_req = "https://ipinfo.io/%s" % asn
            time.sleep(1)

            if not os.path.exists(asn):
                os.system("timeout 3 wget " + as_req)

            try:
                h = open(asn, "r")
                doc = h.read()
                soup = BeautifulSoup(doc, 'html.parser')
                summary = soup.find(id="summary")
                tr_lst = summary.find_all('tr')

                lst = []
                for tr in tr_lst:
                    if "Related Domain" in str(tr):
                        td_lst = tr.find_all('td')
                        dom = td_lst[1].get_text()
                        break
            except:
                print ("File Not Found")
                dom = ""

        hostname = ""
        if "hostname" in js.keys():
            hostname = js["hostname"].strip()
                
        if dom == "":
            dom = "none"

        of.write(str(num) + ", " + domain + ", " + dom + ", " + hostname + "\n")
        print (num, ") ", domain, ", ", dom, ", ", hostname)
        num = num + 1
        time.sleep(1)

def main():
    if len(sys.argv) != 5:
        usage()

    f = open(sys.argv[1], "r")
    g = open(sys.argv[2], "w")
    start = int(sys.argv[3])
    end = int(sys.argv[4])

    crawler(f, g, start, end)

    f.close()
    g.close()

if __name__ == "__main__":
    main()
