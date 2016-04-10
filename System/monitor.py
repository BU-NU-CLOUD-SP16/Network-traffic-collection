import time
from influxdb import InfluxDBClient
from dbread import CreateBatch
from multiprocessing import Pool
import system

# Splits the writing stage to N pcap files written at a time
def execN(N,dir):
	pcaps = [None]*N
	for x in range(1,N+1):
		pcaps[x-1] = "{}{}.pcap".format(dir,x)
	return pcaps

def listsum(numList):
		if len(numList) == 1:
			return numList[0]
		else:
			return numList[0] + listsum(numList[1:])

def readpcaps(N,directory,runs,client):

	masterpcap = execN(N, directory)

	# Parallel worker processes for faster reading
	poolread = Pool(processes= N)
	result = poolread.map_async(CreateBatch, masterpcap)
	# obtain the actual collection of batches
	v = result.get()
	poolread.close()
	poolread.join()

	# for a whole batch write
	batch=[]
	for i in v:
		batch += i

	#write files to database first checkpoint
	t0 = time.time()
	client.write_points(batch, time_precision='ms')
	# write files to database second checkpoint
	t1 = time.time()

	# obtain total number of writes
	tcount = 0
	for i in v:
		tcount += len(i)

	# output performance of writing results to DB
	influx = t1 - t0
	rate = float(tcount) / influx
	# write to log
	f = open("log.txt", "wb")
	f.write("SUCCESS. TIME INFLUX: {} WRITE SPEED PER REQUEST: {} DB: Traffic_{}\n\n".format(influx, rate,runs))
	f.close()

def writestream(count,array,M):
	runs,host,port = system.givevars()
	t0 = time.time()
	client = InfluxDBClient(host.rstrip(), port.rstrip(), database='{"Traffic"_{}_{}'.format(runs,M))
	client.create_database('{"Traffic"_{}_{}'.format(runs,M))
	client.write_points(array,time_precision="ms")
	t1 = time.time()
	influx = t1 - t0
	rate = float(count) / influx

	f = open("log.txt", "wb")
	f.write("SUCCESS. TIME INFLUX: {} WRITE SPEED PER REQUEST: {} DB: Traffic_{}_{}\n".format(influx, rate,runs,M))
	f.close()