import sys
import smtplib

# insert the sender email address
sender = "hwlee2014@mmlab.snu.ac.kr"
# insert the receivers email address
receivers = ["hwlee2014@mmlab.snu.ac.kr"]

def usage():
    print ("Make the entire hash list")
    print ("python3 entire.py <first list> <retry list> <output file>")
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
    if len(sys.argv) != 4:
        usage()

    f = open(sys.argv[1], "r")
    g = open(sys.argv[2], "r")
    of = open(sys.argv[3], "w")

    for line1 in g:
        num1 = int(line1.strip().split(",")[0])

        for line2 in f:
            num2 = int(line2.strip().split(",")[0])
            if num1 > num2:
                of.write(line2)
            elif num1 == num2:
                of.write(line1)
                break

    f.close()
    g.close()
    of.close()

    title = "Combine the original one with the retry one complete"
    msg = "complete"
    send_email(title, msg)

if __name__ == "__main__":
    main()
