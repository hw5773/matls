import sys
import os
import smtplib

# insert the sender email address
sender = "hwlee2014@mmlab.snu.ac.kr"
# insert the receivers email address
receivers = ["hwlee2014@mmlab.snu.ac.kr"]

def usage():
    # input the usage of this script
    print ("This script is the skeleton for python3")
    # input the command to execute this script
    print ("python3 scalability.py")
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
    if len(sys.argv) == 1:
        start = 0
        end = 16
    elif len(sys.argv) == 3:
        start = int(sys.argv[1])
        end = int(sys.argv[2])
    else:
        usage()

    for i in range(start, end+1):
        cmd1 = "/home/dist/matls/scripts/multirun.sh https://www.matls.com 50%02d %d 2>/dev/null" % (17-i, i)
        print (cmd1)
        os.system(cmd1)
        title = "[matls] The experiment is on going with %d middleboxes" % i
        msg = "The experiment is on going with %d middleboxes" % i
        send_email(title, msg)
    # insert the title and the message you want.
    title = "[matls] The experiment is finished"
    msg = "The experiment is finished"

    # send the email to the receivers from sender.
    send_email(title, msg)    

if __name__ == "__main__":
    main()
