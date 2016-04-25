import sys
from subprocess import Popen, PIPE, check_output, call
import matplotlib.pyplot as plt
import numpy as np

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

        cmd0 = "httperf --hog --server facebook.com --port 80 --rate 1000 --num-conn 200000000 &"
        cmd1 = "tcpdump port 80 -i wlan0 -U -w - &"
        cmd2 = "python readpcap_v2.py {}".format(N)
        cmd3 = "python detect.py {}".format(N)

        # RUN HTTPERF, DIRECT TCPDUMP TO READPCAP, AND THEN DETECT. PERF RESULTS APPENDED TO RESULT ARRAYS
        p = Popen(cmd0, shell=True,stdout=PIPE)
        p1 = Popen(cmd1, shell=True, stdout=PIPE)
        p2 = Popen(cmd2, shell=True, stdin=p1.stdout, stdout=PIPE)
        p.kill()
        p1.kill()
        p2r = p2.communicate()[0]
        p3 = check_output(cmd3, shell=True,stdin=PIPE)
        Rresults.append(float(p2r.replace("\n","")))
        Dresults.append(float(p3.replace("\n","")))

    # TURN RESULTS INTO NUMPY ARRAYS
    Rresults = np.float64(1.00) * Rresults
    Dresults = np.float64(1.00) * Dresults

    fig = plt.figure()

    fig, ax = plt.subplots()
    index = np.arange(len(Nlist))
    bar_width = 0.35
    opacity = 0.4
    error_config = {'ecolor': '0.3'}
    plt.gca().get_xaxis().get_major_formatter().set_useOffset(False)

    rects1 = plt.bar(index, Rresults, bar_width,
                     alpha=opacity,
                     color='b',
                     error_kw=error_config,
                     label='Performance Test of Packet Collection')

    rects2 = plt.bar(index + bar_width, Dresults, bar_width,
                     alpha=opacity,
                     color='r',
                     error_kw=error_config,
                     label='Performance Test of Packet Detection')

    plt.xlabel('Number of Requests')
    plt.ylabel('Latency (Time/Packet')
    plt.title('Performance Testing')
    plt.legend()
    plt.tight_layout()
    plt.xticks(index + bar_width, (Nlist))
    plt.savefig('perf.png', dpi=300)






