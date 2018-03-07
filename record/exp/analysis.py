import sys
import os
import smtplib

# insert the sender email address
sender = "hwlee2014@mmlab.snu.ac.kr"
# insert the receivers email address
receivers = ["hwlee2014@mmlab.snu.ac.kr"]

def usage():
    # input the usage of this script
    print ("This script is to analyze the result")
    # input the command to execute this script
    print ("python3 analysis.py <log file>")
    exit(1)

def main():
    # check the number of arguments. change the number in the below statement according to the design.
    if len(sys.argv) != 2:
        usage()

    f = open(sys.argv[1], "r")
    f.readline()

    result = {}

    for line in f:
        tmp = line.strip().split(",")

if __name__ == "__main__":
    main()
