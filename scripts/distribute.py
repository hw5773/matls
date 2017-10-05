import sys

sender = "hwlee2014@mmlab.snu.ac.kr"
receivers = ["hwlee2014@mmlab.snu.ac.kr"]

hash_lst = ["md5", "sha1", "sha224", "sha256", "ripemd160"]
out = {}
coll = {}
err = open("err.log", "w")

def usage():
    print ("Get contents from each domain")
    print ("python3 distribute.py")
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

def analysis(h):
	name = "hash_%s.csv"

	f = open(name, "r")

	for line in f:
		tmp = line.split(", ")

	f.close()

def main():
	if len(sys.argv) != 1:
		usage()

	for h in hash_lst:
		name1 = "hash_%s.out" % h
		name2 = "hash_%s.col" % h
		out[h] = open(name1, "w")
		col[h] = open(name2, "w")
		analysis(h)

	for h in hash_lst:
		out[h].close()
		col[h].close()
		
	

if __name__ == "__main__":
	main()
