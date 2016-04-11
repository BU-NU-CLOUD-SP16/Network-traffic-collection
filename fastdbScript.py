from influxdb import InfluxDBClient
from influxdb import SeriesHelper
import time,datetime

def createCommand(sip, dip, domain, url, user_agent, referrer, code, action, bytes, type):
    jsonArray = []

    for i in range(0,1000):

        json_body = {
                "measurement": "http",
                "tags": {
                    "source_ip_address=":sip,
                    "source_port":80,
                    "destination_ip_address":dip,
                    "domain":domain,
                    "url":url,
                    "user_agent_string":user_agent,
                    "web_referer":referrer,
                    "result_code":code,
                    "action":action,
                    "bytes_sent_and_recieved":bytes,
                    "content_type":type,
            },
            "time": datetime.datetime.now().isoformat(),
            "fields": {
                "value": 12.0
            }
            }
        jsonArray.append(json_body)
    return jsonArray


myclient = InfluxDBClient(host='127.0.0.1', port=8086, database='db_3')
myclient.create_database('db_3')

class MySeriesHelper(SeriesHelper):
    # Meta class stores time series helper configuration.
    class Meta:
        # The client should be an instance of InfluxDBClient.
        client = myclient
        # The series name must be a string. Add dependent fields/tags in curly brackets.
        series_name = 'http'
        # Defines all the fields in this time series.
        fields = ['bytes','code']
        # Defines all the tags for the series.
        tags = ['sip', 'dip', 'domain', 'url', 'user_agent', 'referrer', 'action','type']
        # Defines the number of data points to store prior to writing on the wire.
        bulk_size = 1001
        # autocommit must be set to True when using bulk_size
        autocommit = True

################ NEW METHOD #############################
for i in range(0,10000):
    MySeriesHelper(action='GET', bytes=78,code=404,dip='4.4.4.4', domain='google.com',referrer='somereferrer',sip='127.127.12.127',type='html/plain', url='http://google.com', user_agent='Someagent')

# To manually submit data points which are not yet written, call commit:
t0 = time.time()
MySeriesHelper.commit()
t1 = time.time()
influx1 = t1-t0
print("NEW METHOD RATE: {}".format(float(1000/influx1)))

############### PREVIOUS METHOD #########################

v = createCommand("127.127.12.127", "4.4.4.4", "google.com", "http://google.com", "SomeAgent", "Somereferrer","404", "GET", "78", "html/plain")

client = InfluxDBClient(host='127.0.0.1', port=8086, database='db_3')
client.create_database('db_3')
t0 = time.time()
client.write_points(v)
t1 = time.time()
influx2 = t1-t0
print("PREV METHOD RATE: {}".format(float(1000/influx2)))