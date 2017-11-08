from bs4 import BeautifulSoup
import sys
import os
import smtplib
import socket
import urllib.request
import json

# insert the sender email address
sender = "hwlee2014@mmlab.snu.ac.kr"
# insert the receivers email address
receivers = ["hwlee2014@mmlab.snu.ac.kr"]

net_domain = {}
dom_cdn = {}
success = 0

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
						s1 = fn + ", " + dom + ", " + target + ", " + str(dom == target)
						dom_lst = []
						target_lst = []

						ais1 = socket.getaddrinfo(dom, 0, 0, 0, 0)
						ais2 = socket.getaddrinfo(target, 0, 0, 0, 0)

						for result in ais1:
							dom_lst.append(result[-1][0])
						
						for result in ais2:
							target_lst.append(result[-1][0])

						dom_lst = set(dom_lst)
						target_lst = set(target_lst)

						union = dom_lst.union(target_lst)

						if dom in dom_cdn:
							cdn = dom_cdn[dom]
						else:
							cdn = "NONE"

						if dom == target:
							s2 = "True, " + cdn
						else:

							if len(union) > 0:
								s2 = "True"
								for ip in union:
									net = '.'.join(ip.split(".")[0:3])
								
									if net in net_domain:
										s2 = s2 + ", " + net_domain[net]
										break
							else:
								s2 = "False"
								for ip in target_lst:
									net = '.'.join(ip.split(".")[0:3])

									if net in net_domain:
										s2 = s2 + ", " + net_domain[net]
										break

							if s2 == "True" or s2 == "False":
								s2 = s2 + ", NONE"
								s = s1 + ", " + s2 + "\n"
								print (s)
								err.write("%s, no related domain\n" % fn)
								break

						s = s1 + ", " + s2 + "\n"
						print (s)

						of.write(s)
					except:
						err.write("%s, no action in\n" % fn)
					break
		success = success + 1
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

	f = open("nslookup_rd_cdn", "r")

	for line in f:
		cdn = line.strip().split(":")[1].strip()

		if "NO" in cdn:
			continue

		tmp = line.strip().split(":")[0].split(",")
		ip = tmp[2].split("/")[-1].strip()
		network = '.'.join(ip.split(".")[0:3])
		domain = tmp[1].strip()
		net_domain[network] = cdn
		dom_cdn[domain] = cdn
		print (network, ": ", cdn)

	of = open(fname, "w")
	err = open(ename, "w")

	of.write("file name, action, target, domain, same URL?, common IP?, CDN\n")

	num = 0
	for root, dirs, files in os.walk("./"):
		for fn in files:
			if ".html" in fn:
				fname = os.path.join(root, fn)
				dom = '.'.join(fn.split("_")[-1].strip().split(".")[0:-1])
				search_key(dom, fname, of, err)
				num = num + 1

				if num % 10000 == 0:
					title = "Progress Report"
					msg = "Finding the Keywords in Privacy Policy on Going: %s\n" % num
#					send_email(title, msg)

	of.close()
	err.close()

	print ("Complete: %d / %d" % (success, num))

	cname = sys.argv[1] + ".result"
	com = open(cname, "w")
	com.write(str(success))
	com.write("\n")
	com.write(str(num))
	com.close()

#	title = "Experiment Complete"
#	msg = "Privacy Search Complete"
#	send_email(title, msg)

if __name__ == "__main__":
	main()
