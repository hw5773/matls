import sys
import smtplib

sender = "hwlee2014@mmlab.snu.ac.kr"
receivers = ["hwlee2014@mmlab.snu.ac.kr"]

hash_lst = ["sha256"]
out = {}

def usage():
	print ("python3 freq_analysis.py")
	exit(-1)

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

def initialize():
	for h in hash_lst:
		out[h] = {}
		out[h][4] = {}

		for i in range(65536):
			out[h][4][i] = []

		freq(h)

def freq(h):
	fname = "hash_" + h + ".csv"
	ofname = h + "_coll.csv"

	f = open(fname, "r")
	of = open(ofname, "w")

	f.readline()
	n = 0
	for line in f:
		n = n + 1
		tmp = line.strip().split(",")
		num = int(tmp[0].strip())
		size = int(tmp[2].strip())
		hvalue = tmp[4].strip()

		idx4 = int(hvalue[0:4], 16)
		
		if hvalue in out[h][4][idx4]:
			of.write(line)
		else:
			out[h][4][idx4].append(hvalue)

		if (n % 1000000) == 0:
			msg = "%s: %d lines complete." % (h, n)
			print (msg)
			send_email(msg)

	of.close()

	write_freq(h)
	
def write_freq(h):
	ofname = h + "_freq.csv"

	of = open(ofname, "w")

	for i in range(65536):
		s = hex(i)[4:] + ", " + str(len(out[h][4][i])) + "\n"
		of.write(s)

	of.close()

	msg = "%s is complete" % h
	send_email(msg)

def main():
	initialize()
	msg = "Experiment is complete"
	send_email(msg)

if __name__ == "__main__":
	main()
