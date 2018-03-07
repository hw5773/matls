import sys
import os
import smtplib
import numpy as np

# insert the sender email address
sender = "hwlee2014@mmlab.snu.ac.kr"
# insert the receivers email address
receivers = ["hwlee2014@mmlab.snu.ac.kr"]

def usage():
    # input the usage of this script
    print ("This script is to analyze the result")
    # input the command to execute this script
    print ("python3 analysis.py <log file> <output file>")
    exit(1)

def main():
    # check the number of arguments. change the number in the below statement according to the design.
    if len(sys.argv) != 3:
        usage()

    f = open(sys.argv[1], "r")
    f.readline()

    g = open(sys.argv[2], "w")
    g.write("Num of Writers, Average, Max, Min\n")

    result = {}

    for line in f:
        tmp = line.strip().split(",")
        num = int(tmp[0])

        if not (num in result.keys()):
            result[num] = []

        result[num].append(int(tmp[2]))

    for k in result.keys():
        s = "%d, %f, %d, %d\n" % (k, np.mean(result[k]), max(result[k]), min(result[k]))
        g.write(s)

if __name__ == "__main__":
    main()
