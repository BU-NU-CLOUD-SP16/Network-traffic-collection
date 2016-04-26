import sys
from subprocess import Popen, PIPE, check_output, call

if __name__ == '__main__':
    # PERFORMANCE TESTER FOR TRAFFIC COLLECTION / MALICIOUS TRAFFIC DETECTION
    ##
    # NUMBER OF REQUESTS FROM USER INPUT
    arglist = sys.argv
    argnum = len(arglist)
    Nlist = arglist[1:(argnum)]
    for n in Nlist:
        n = int(n)

    # ARRAY FOR STORING RESULTS
    Rresults = []
    Dresults = []

    # START SUBPROCESSES
    for n in range(0, len(Nlist)):
        N = Nlist[n]

        cmd1 = "tcpdump port 80 -i eth1 -U -w - &"
        cmd2 = "python readpcap_v2.py {}".format(N)
        cmd3 = "python detect.py {}".format(N)

        # RUN HTTPERF, DIRECT TCPDUMP TO READPCAP, AND THEN DETECT. PERF RESULTS APPENDED TO RESULT ARRAYS
        p1 = Popen(cmd1, shell=True, stdout=PIPE)
        p2 = Popen(cmd2, shell=True, stdin=p1.stdout, stdout=PIPE)
        p1.kill()
        p2r = p2.communicate()[0]
        p3 = check_output(cmd3, shell=True,stdin=PIPE)
        Rresults.append(float(p2r.replace("\n","")))
        Dresults.append(float(p3.replace("\n","")))
    
    for n in range(0, len(Nlist)):
        N = Nlist[n]
        with open("perf_log.txt", "a") as myfile:
            myfile.write("READING LATENCY FOR {} REQUESTS: {} -- DETECTION LATENCY FOR {} REQUESTS: {}".format(N,Rresults[n],N,Dresults[n]))


