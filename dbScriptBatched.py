__author__ = 'akashkakumani'


import time
import datetime
from influxdb import InfluxDBClient




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



client = InfluxDBClient(host='127.0.0.1', port=8086, database='newDB')

v = createCommand("127.127.12.127", "4.4.4.4", "google.com", "http://google.com", "SomeAgent", "Somereferrer",
       "404", "GET", "78", "html/plain")

t0 = time.time()

client.write_points(v)

t1 = time.time()

total = t1-t0


print("TOTAL::::")
print(total)