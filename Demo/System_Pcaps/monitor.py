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

	client.write_points(batch, time_precision='ms')

	f.close()
