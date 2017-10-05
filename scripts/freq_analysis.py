import sys
import smtplib

sender = "hwlee2014@mmlab.snu.ac.kr"
receivers = ["hwlee2014@mmlab.snu.ac.kr"]

hash_lst = ["md5", "sha1", "sha224", "sha256", "ripemd160"]
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
		out[h][1] = {}
		out[h][2] = {}

		for i in range(16):
			out[h][1][i] = []

		for i in range(256):
			out[h][2][i] = []

		freq(h)

def freq(h):
	fname = "hash_" + h + ".csv"
	ofname1 = h + "_coll1.csv"
	ofname2 = h + "_coll2.csv"

	f = open(fname, "r")
	of1 = open(ofname1, "w")
	of2 = open(ofname2, "w")

	f.readline()
	n = 0
	for line in f:
		n = n + 1
		tmp = line.strip().split(",")
		num = int(tmp[0].strip())
		size = int(tmp[3].strip())
		hvalue = tmp[5].strip()

		idx1 = int(hvalue[0], 16)
		idx2 = int(hvalue[0:2], 16)
		
		if hvalue in out[h][1][idx1]:
			of1.write(line)
		else:
			out[h][1][idx1].append(hvalue)

		if hvalue in out[h][2][idx2]:
			of2.write(line)
		else:
			out[h][2][idx2].append(hvalue)

		if (n % 1000) == 0:
			print (h, ": ", n, " lines complete.")

	of1.close()
	of2.close()

	write_freq(h)
	
def write_freq(h):
	ofname1 = h + "_freq1.csv"
	ofname2 = h + "_freq2.csv"

	of1 = open(ofname1, "w")
	of2 = open(ofname2, "w")

	for i in range(16):
		s = hex(i)[2:] + ", " + str(len(out[h][1][i])) + "\n"
		of1.write(s)

	for i in range(256):
		s = hex(i)[2:] + ", " + str(len(out[h][2][i])) + "\n"
		of2.write(s)

	of1.close()
	of2.close()

	msg = "%s is complete" % h
	send_email(msg)

def main():
	initialize()

if __name__ == "__main__":
	main()
