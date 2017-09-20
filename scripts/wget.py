import os
import sys
import time
import random

sender = "hwlee2014@mmlab.snu.ac.kr"
receivers = ["hwlee2014@mmlab.snu.ac.kr"]

def usage():
    print ("Get contents from each domain")
    print ("python3 contents.py <top domains> <start> <end>")
    exit(1)

def send_email(start, end):
    message = """From: Hyunwoo Lee <hwlee2014@mmlab.snu.ac.kr>
To: Hyunwoo Lee <hwlee2014@mmlab.snu.ac.kr>
Subject: Content Experiment Report <%s, %s>

The Experiment for Content from %s to %s is completed.
""" % (start, end)

    try:
        smtpObj = smtplib.SMTP(host="old-mmlab.snu.ac.kr")
        smtpObj.sendmail(sender, receivers, message)
        print ("Successfully sent email")
    except SMTPException:
        print ("Error: unable to send email")


def get_contents(f, start, end):
    n = start
    for i in range(start - 1):
        f.readline()

    for line in f:
        if n > end:
            break
        tmp = line.strip().split(",")
        num = int(tmp[0].strip())
        dom = "www." + tmp[1].strip()
        cmd = "wget --dns-timeout 3 --connect-timeout 3 --read-timeout 3 --no-clobber --convert-links --random-wait -p -E -e robots=off -U mozilla -P %s %s" % (num, dom)
        print ("%s) %s" % (num, dom))
        try:
            os.system(cmd)
        except:
            continue

        r = random.uniform(0, 5)
        time.sleep(r)



def main():
    if len(sys.argv) != 4:
        usage()

    f = open(sys.argv[1], "r")
    start = int(sys.argv[2])
    end = int(sys.argv[3])
    
    get_contents(f, start, end)

    f.close()
    send_email(start, end)

if __name__ == "__main__":
    main()
