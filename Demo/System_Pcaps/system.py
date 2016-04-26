import monitor
from influxdb import InfluxDBClient
import fileinput
import sys
########################################################################################
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

def givevars():
    global runs,host,port
    return runs,host,port

if __name__=="__main__" :

    from detect import detect
    from multiprocessing import Process

    global directory, N, MAXREQUESTS, DETECTLOADS, host, port, runs
    initparams()

    client = InfluxDBClient(host, port, database='Traffic",username='grafana',password='grafana')
    client.create_database('Traffic")
    monitor.readpcaps(N,directory,runs,client)

    p = Process(target=detect(runs,host,port))
    p.start()

