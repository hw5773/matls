import os

def usage():
    print ("SCP every directories to mbox4")
    exit(-1)

def main():
    num = 0
    for root, dirs, files in os.walk("./"):
        for d in dirs:
            if "_" in d:
                cmd = "sshpass -p mmlab2015 scp -r %s hwlee@147.46.114.149:~/content" % d
                os.system(cmd)
                num = num + 1
                print (num, ") ", cmd)

if __name__ == "__main__":
    main()
