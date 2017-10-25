import sys
import os
import smtplib

# insert the sender email address
sender = "hwlee2014@mmlab.snu.ac.kr"
# insert the receivers email address
receivers = ["hwlee2014@mmlab.snu.ac.kr"]

cdns = ["accelia", "akamai", "ananke", "aryaka", "azion", "azure", "bitgravity", "bitrix", "cachefly", "cdn77", "cdnetworks", "cdnsun", "cdnvideo", "cedexis", "chinacache", "chinanetcenter", "cloudflare", "cloudfront", "dnion", "edgecast", "fastly", "g-cdn", "google", "hibernia", "inap", "incapsula", "instartlogic", "isprime", "leaseweb", "level3", "limelight", "maxcdn", "ngenix", "powercdn", "rackspace", "reflected", "scaleengine", "section.io", "skypark", "taobao", "tencent", "turbobytes", "txnetworks", "xinnet", "yotta", "keycdn", "stackpath", "instart logic", "medianova", "airee", "panther", "swiftcdn"]

def usage():
	print ("Search the keyword in the document.")
	print ("python3 summarize.py <output file name> <keyword>")
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

def search_key(fn, of, err, keywords):
	write_fname = False

	try:
		f = open(fn, "r")
		tmp1 = f.read()
		tmp2 = tmp1.split("\n")

		for e1 in tmp2:
			tmp3 = e1.split(".")

			for e2 in tmp3:
				for k in keywords:
					if k in e2.lower():
						if " " not in e2:
							continue
						else:
							if write_fname == False:
								of.write(fn + ":\n")
								write_fname = True
							of.write(e2 + "\n")
							break
	except:
		e = "%s\n" % fn
		err.write(e)

	if write_fname == True:
		of.write("\n")

def main():
	if (len(sys.argv) < 2) or (len(sys.argv) > 3):
		usage()

	if len(sys.argv) == 3:
		keywords = [sys.argv[2]]
	elif sys.argv[2] == "cdn":
		keywords = cdns
	else:
		keywords = ["proxy", "proxies", "third party", "third parties", "content delivery network", "cdn", "processor"]

	fname = sys.argv[1] + ".out"
	ename = sys.argv[1] + ".err"

	of = open(fname, "w")
	err = open(ename, "w")

	num = 0
	for root, dirs, files in os.walk("./"):
		for fn in files:
			if ("privacy" in fn) or ("term" in fn):
				fname = os.path.join(root, fn)
				search_key(fname, of, err, keywords)
				num = num + 1

				if num % 10000 == 0:
					title = "Progress Report"
					msg = "Finding the Keywords in Privacy Policy on Going: %s\n" % num

	of.close()
	err.close()

	title = "Experiment Complete"
	msg = "Privacy Search Complete"
	send_email(title, msg)

if __name__ == "__main__":
	main()
