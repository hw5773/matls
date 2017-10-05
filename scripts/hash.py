from bs4 import BeautifulSoup
import os
import sys
import hashlib
import smtplib
import time
import json

sender = "hwlee2014@mmlab.snu.ac.kr"
receivers = ["hwlee2014@mmlab.snu.ac.kr"]

hash_lst = ["md5", "sha1", "sha224", "sha256", "ripemd160"]
out = {}
err = open("err.log", "w")

def usage():
    print ("Get contents from each domain")
    print ("python3 hash.py <input file>")
    exit(1)

def send_email(msg):
	message = """From: Hyunwoo Lee <hwlee2014@mmlab.snu.ac.kr>
To: Hyunwoo Lee <hwlee2014@mmlab.snu.ac.kr>
Subject: Experiment Report

The experiment is on going:
%s
""" % (msg)

	try:
		smtpObj = smtplib.SMTP(host="old-mmlab.snu.ac.kr")
		smtpObj.sendmail(sender, receivers, message)
		print ("Successfully sent email")
	except SMTPException:
		print ("Error: unable to send email")

def store_hash(num, js):
    num = num + 1
    ip = js['ip']
    domain = js['domain']

    try:
        data = js['data']['http']['response']['body'].encode('utf8')
    except:
        s = "%s) [Error] Key error\n" % num
        err.write(s)
        return num

    size = len(data)
    start_time = 0
    end_time = 0
    hash_val = 0
#    print ("Hashing the data %s" % num)

    for lib in hash_lst:
        h = hashlib.new(lib)
        try:
            start_time = time.time()
            h.update(data)
            end_time = time.time()
            hash_val = h.hexdigest()
        except:
            s = "%s) [Error] Error making the hash value\n" % num
            err.write(s)
        s = "%s, %s, %s, %s, %s, %s\n" % (num, domain, ip, size, end_time - start_time, hash_val)
        out[lib].write(s)

    if num % 100000 == 0:
        msg = "Experiment is on going. %s data are processed" % num
        send_email(msg)

    return num

def main():
    if len(sys.argv) != 2:
        usage()

    f = open(sys.argv[1], "r")
    
    for h in hash_lst:
        name = "hash_%s.csv" % h
        out[h] = open(name, "w")
        out[h].write("num, domain, ip address, size, hashing time, hash\n")

    num = 0
    for line in f:
        js = json.loads(line)
#        print ("Keys: ", js['data']['http']['response'].keys())
        num = store_hash(num, js)

    f.close()

    for h in hash_lst:
        out[h].close()

    err.close()

if __name__ == "__main__":
    main()
