from bs4 import BeautifulSoup
import os
import sys
import hashlib

hash_lst = ["md5", "sha1", "sha224", "sha256", "ripemd160"]
out = {}

def usage():
    print ("Get contents from each domain")
    print ("python3 contents.py <top domains> <result file> <start number> <num of domains>")
    exit(1)

def get_index_file(dname, dom):
    path = dname + "/header"
    index = dname + "/index"
    num = int(dname.split("_")[0])
    cmd = "curl -A \"Mozilla/5.0\" -L -s -D %s \"www.%s\" > %s" % (path, dom, index)
    os.system(cmd)
    
    for lib in hash_lst:
        h = hashlib.new(lib)
        try:
            c = open(index, "rb")
        except:
            break
        try:
            h.update(c.read())
            hash_val = h.hexdigest()
        except:
            c.close()
        try:
            statinfo = os.stat(index)
        except:
            break
        size = statinfo.st_size
        s = "%s, %s, %s\n" % (num, size, hash_val)
        out[lib].write(s)

    print ("  Get: ", index)

def get_content_lst(dname):
    index = dname + "/index"
    lst = []
    try:
        f = open(index, "r")
    except:
        return []
    try:
        doc = f.read()
    except:
        f.close()
        return lst

    soup = BeautifulSoup(doc, 'html.parser')

    for img in soup.findAll('img'):
        try:
            if img['src'] not in lst:
                lst.append(img['src'])
        except:
            continue

    for script in soup.findAll('script'):
        try:
            if script['src'] not in lst:
                lst.append(script['src'])
        except:
            continue

    for video in soup.findAll('video'):
        try:
            if video['src'] not in lst:
                lst.append(video['src'])
        except:
            continue

    f.close()

    return lst

def get_contents(dname, cdname, dom):
    index = dname + "/index"
    try:
        f = open(index, "r")
    except:
        return 0
    try:
        doc = f.read()
    except:
        f.close()
        return 0

    soup = BeautifulSoup(doc, 'html.parser')

    lst = get_content_lst(dname)

    n = len(lst)

    for i in range(n):
        hdr = cdname + "/header.%s" % i
        body = cdname + "/body.%s" % i
        num = int(dname.split("_")[0])
        content = lst[i]

        try:
            if content[0:2] == "//":
                content = "http:" + content
            elif content[0] == "/" and content[1] != "/":
                content = "http://" + dom + content
            elif content[0:4] != "http":
                content = "http://" + dom + "/" + content
        except:
            continue


        cmd = "curl -A \"Mozilla/5.0\" -L -s -D %s \"%s\" > %s" % (hdr, content, body)
        cname = cdname + "/name.%s" % i
        name = open(cname, "w")
        name.write(content)
        name.close()

        os.system(cmd)
        print ("  Progress: ", i+1, " of ", n)

        try:
            statinfo = os.stat(body)
        except:
            continue
        size = statinfo.st_size

        if size == 0:
            continue

        for lib in hash_lst:
            h = hashlib.new(lib)
            try:
                c = open(body, "rb")
                h.update(c.read())
            except:
                break
            hash_val = h.hexdigest()
            c.close()
            s = "%s.%s, %s, %s\n" % (num, i, size, hash_val)
            out[lib].write(s)

    return n

def content(f, of, start, domains):
    num = 0
    for line in f:
        num = num + 1

        if num < start:
            continue
        elif num >= start + domains:
            break

        dname = line.strip().replace(", ", "_")
        dom = dname.split("_")[-1]
        cdname = dname + "/contents"
        print ("Domain Name: ", dname)
        os.mkdir(dname)
        os.mkdir(cdname)
        get_index_file(dname, dom)
        n = get_contents(dname, cdname, dom) # n: # of contents + index.html
        s = str(num) + ", " + str(n) + "\n"
        of.write(s)

def main():
    if len(sys.argv) != 5:
        usage()

    f = open(sys.argv[1], "r")
    of = open(sys.argv[2], "w")
    start = int(sys.argv[3])
    domains = int(sys.argv[4])
    
    for h in hash_lst:
        name = "%s_%s_%s.csv" % (h, start, start + domains - 1)
        out[h] = open(name, "w")
        out[h].write("num, size, hash\n")

    content(f, of, start, domains)

    f.close()
    of.close()

    for h in hash_lst:
        out[h].close()

if __name__ == "__main__":
    main()
