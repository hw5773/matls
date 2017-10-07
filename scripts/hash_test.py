import sys
import os
import smtplib
import hashlib

# insert the sender email address
sender = "hwlee2014@mmlab.snu.ac.kr"
# insert the receivers email address
receivers = ["hwlee2014@mmlab.snu.ac.kr"]

def usage():
	# input the usage of this script
	print ("Hashing every index files")
	# input the command to execute this script
	print ("python3 hash_test.py <output file> <num of directories>")
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
	if len(sys.argv) != 3:
		usage()

	of = open(sys.argv[1], "w")
	num = int(sys.argv[2])
	h = hashlib.sha256()

	for i in range(1, num+1):
		fname = "./%d/index.html" % i
		try:
			with open(fname, "rb") as f:
				data = f.read()
				h.update(data)
				s = "%s, %s\n" % (i, h.hexdigest())
				of.write(s)
		except:
			s = "%s, no file exception\n" % i
			of.write(s)

		if i % 1000 == 0:
			print ("Progress: %d / 798441" % i)

	of.close()

	# insert the title and the message you want.
	title = "Making the groundtruth complete"
	msg = "The output file is %s" % sys.argv[1]

	# send the email to the receivers from sender.
	send_email(title, msg)	

if __name__ == "__main__":
	main()
