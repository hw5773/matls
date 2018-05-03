import sys
import os
import smtplib

# insert the sender email address
sender = "hwlee2014@mmlab.snu.ac.kr"
# insert the receivers email address
receivers = ["hwlee2014@mmlab.snu.ac.kr"]

def usage():
    # input the usage of this script
    print ("Experiment for Modification Record")
    # input the command to execute this script
    print ("python3 exp.py <maximum number of writers> <number of orders> <file name>")
    exit(1)

def main():
    # check the number of arguments. change the number in the below statement according to the design.
    if len(sys.argv) != 4:
        usage()

    max_writers = int(sys.argv[1])
    max_order = int(sys.argv[2])
    file_name = sys.argv[3]

    cmd = "cp log_file %s" % file_name
    os.system(cmd)

    for i in range(max_writers + 1):
        for j in range(1, max_order + 1):
            cmd = "./test_record %d %d %s" % (i, j, file_name)
            os.system(cmd)

if __name__ == "__main__":
    main()
