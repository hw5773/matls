import sys
import os
import smtplib
import hashlib

# insert the sender email address
sender = "hwlee2014@mmlab.snu.ac.kr"
# insert the receivers email address
receivers = ["hwlee2014@mmlab.snu.ac.kr"]

INDEX = "index.html"
NUM_OF_DIRECTORY = 798441

def usage():
    # input the usage of this script
    print ("Hashing every index files")
    # input the command to execute this script
    print ("python3 hash_test.py <prefix> <ip> <port> <list>")
    exit(1)

def send_email(title, msg):
    message = """From: Hyunwoo Lee <hwlee2014@mmlab.snu.ac.kr>
To: Hyunwoo Lee <hwlee2014@mmlab.snu.ac.kr>
Subject: %s

The experiment is on going:
%s
""" % (title, msg)

    try:
        smtpObj = smtplib.SMTP(host="old-mmlab.snu.ac.kr")
        smtpObj.sendmail(sender, receivers, message)
        print ("Successfully sent email")
    except SMTPException:
        print ("Error: unable to send email")

def main():
    # check the number of arguments. change the number in the below statement according to the design.
    if len(sys.argv) != 5:
        usage()

    prefix = sys.argv[1]
    fname = "%s_hash.out" % prefix
    of = open(fname, "w")
    ip = sys.argv[2]
    port = int(sys.argv[3])
    lst = open(sys.argv[4], "r")

    n = 0
    for line in lst:
        i = int(line.strip().split(",")[0])
        cmd = "wget --ca-certificate=ca_carol.pem https://%s:%d/%d/index.html -O %s.html" % (ip, port, i, prefix)
        try:
            os.system(cmd)
            f = open(INDEX, "rb")
            data = f.read()
            f.close()
            os.remove(INDEX)
            h = hashlib.sha256()
            h.update(data)
            s = "%s, %s\n" % (i, h.hexdigest())
            of.write(s)
        except:
            s = "%s, no file exception\n" % i
            of.write(s)

        n = n + 1
        if n % 100000 == 0:
            title = "Progress Report: %s" % prefix
            msg = "Progress: %d / 494547" % n
            print (msg)
            send_email(title, msg)

    of.close()

    # insert the title and the message you want.
    title = "Hashing for %s complete" % prefix
    msg = "The output file is %s" % sys.argv[1]

    # send the email to the receivers from sender.
    send_email(title, msg)    

if __name__ == "__main__":
    main()
