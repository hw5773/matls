from bs4 import BeautifulSoup
import sys
import os
import smtplib

# insert the sender email address
sender = "hwlee2014@mmlab.snu.ac.kr"
# insert the receivers email address
receivers = ["hwlee2014@mmlab.snu.ac.kr"]

def usage():
	print ("Search the login form and its target URL.")
	print ("python3 login.py <output file name> <keyword>")
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

def search_key(dom, fn, of, err):
	write_fname = False

	lst = ["login", "log-in", "log_in"]

	try:
		f = open(fn, "r")
		doc = f.read()
		soup = BeautifulSoup(doc, 'html.parser')
		forms = soup.find_all('form')

		for form in forms:
			for k in lst:
				if k in str(form).lower():
					try:
						if write_fname == False:
							of.write(fn + ": " + dom + "\n")
							write_fname = True
						action = form.get('action')
						target = action.split("//")[1].split("/")[0]
						s = fn + ", " + action + ", " + target + ", " + str(dom == target) + "\n"
						print (s)
						of.write(s)
					except:
						err.write("%s, No action in\n" % fn)
					break
	except:
		e = "%s\n" % fn
		err.write(e)

	if write_fname == True:
		#print("\n")
		of.write("\n")

def main():
	if len(sys.argv) != 2:
		usage()

	fname = sys.argv[1] + ".out"
	ename = sys.argv[1] + ".err"

	of = open(fname, "w")
	err = open(ename, "w")

	num = 0
	for root, dirs, files in os.walk("./"):
		for fn in files:
			if "index" in fn:
				fname = os.path.join(root, fn)
				dom = root.split("/")[-1].strip()
				search_key(dom, fname, of, err)
				num = num + 1

				if num % 10000 == 0:
					title = "Progress Report"
					msg = "Finding the Keywords in Privacy Policy on Going: %s\n" % num
#					send_email(title, msg)

	of.close()
	err.close()

#	title = "Experiment Complete"
#	msg = "Privacy Search Complete"
#	send_email(title, msg)

if __name__ == "__main__":
	main()
