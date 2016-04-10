import monitor
from influxdb import InfluxDBClient
import fileinput
import sys
########################################################################################
# for streaming input from stdin case
def streamcheck(count,M):
    global MAXREQUESTS
    if (M == 0):
        M += 1 # begin system
        initparams()
    if(count > MAXREQUESTS):
        M += 1
    return M

# for initializing system parameters from config.txt file
def initparams():
    global directory, N, MAXREQUESTS, DETECTLOADS, host, port, runs

    with open("config.txt") as config:
        params = config.readlines()
        for line in params:
            current = line.split(" ")
            if current[0] == "dir":
                directory = current[1].rstrip()
            if current[0] == "N":
                N = int(current[1])
            if current[0] == "MAXREQUESTS":
                MAXREQUESTS = int(current[1])
            if current[0] == "DETECTLOADS":
                DETECTLOADS = int(current[1])
            if current[0] == "host":
                host = current[1].rstrip()
            if current[0] == "port":
                port = current[1].rstrip()
            if current[0] == "run":
                runs = int(current[1])

# update the number of runs of the program
def updateconfig(runs):
    f = fileinput.FileInput("config.txt", inplace=True)
    for line in f:
        sys.stdout.write(line.replace("run {}".format(runs).rstrip(), "run {}".format(runs+1).rstrip()))
    f.close()

def givevars():
    global runs,host,port
    return runs,host,port

if __name__=="__main__" :

    from detect import detect
    from multiprocessing import Process

    global directory, N, MAXREQUESTS, DETECTLOADS, host, port, runs
    initparams()

    client = InfluxDBClient(host, port, database='Traffic_{}'.format(runs))
    client.create_database('Traffic_{}'.format(runs))
    monitor.readpcaps(N,directory,runs,client)

    p = Process(target=detect(runs,host,port))
    p.start()

    updateconfig(runs)

