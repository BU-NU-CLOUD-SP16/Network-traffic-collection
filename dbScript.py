__author__ = 'akashkakumani'

import time
import datetime
import calendar
import uuid
from influxdb import InfluxDBClient

def createCommand(sip, dip, domain, url, user_agent, referrer, code, action, bytes, type, value):
    json_body = [
            {
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
        ]
    return json_body



client = InfluxDBClient(host='127.0.0.1', port=8086, database='newDB')
t0 = time.time()

n = 0
while(n<1000):
    client.write_points(createCommand("127.127.12.127", "4.4.4.4", "google.com", "http://google.com", "SomeAgent", "Somereferrer",
       "404", "GET", "78", "html/plain", n))
    n+=1
    print(n)

t1 = time.time()

total = t1-t0


print("TOTAL::::")
print(total)