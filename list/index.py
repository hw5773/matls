import sys
import os
import smtplib
import time

sender = "hwlee2014@mmlab.snu.ac.kr"
receivers = ["hwlee2014@mmlab.snu.ac.kr"]

def usage():
    print ("Get the final host")
    print ("python3 index.py <top 1m list> <output file>")
    exit(1)

def send_email(title, msg):
    message = """From: Hyunwoo Lee <hwlee2014@mmlab.snu.ac.kr> 
To: Hyunwoo Lee <hwlee2014@mmlab.snu.ac.kr>
Subject: %s

Get the final hosts: %s
""" % (title, msg)

    try:
        smtp_obj = smtplib.SMTP(host="old-mmlab.snu.ac.kr")
        smtp_obj.sendmail(sender, receivers, message)
        print ("Successfully sent email")
    except SMTPException:
        print ("Error: unable to send email")

def final_host(lst, of):
    for line in lst:
        tmp = line.strip().split(",")
        rank = int(tmp[0])
        domain = tmp[1]
        cmd = "curl -m 10 -L -v -s -o - -I https://%s 2>tmp_%d" % (domain,os.getpid())
        os.system(cmd)
        fname = "tmp_%d" % os.getpid()
        statinfo = os.stat(fname)
        final = ""
        if statinfo.st_size == 0:
            final = "Unaccessible (%s)" % domain
        else:
            final = domain
            t = open("tmp_%d" % (os.getpid()), "rb")

            for ln in t:
                try:
                    s = ln.decode()
                    if "Location:" in s:
                        final = s.split("Location:")[1].strip().split("//")[1].split("/")[0].strip()
                        print ("Final Host (by Location): ", final)
                    if "Host:" in s:
                        final = s.split("Host:")[1].strip()
                        print ("Final Host (by Host): ", final)
                except:
                    continue
            t.close()
        print("%d, %s\n" % (rank, final))
        of.write("%d,%s\n" % (rank, final))

def main():
    if len(sys.argv) != 3:
        usage()

    lst = open(sys.argv[1], "r")
    of = open(sys.argv[2], "w")
    final_host(lst, of)
    os.remove("tmp_%s" % os.getpid())
    lst.close()
    of.close()

    title = "Get the final host from %s" % sys.argv[1]
    msg = "Getting the final host complete"
    send_email(title, msg)

if __name__ == "__main__":
    main()
