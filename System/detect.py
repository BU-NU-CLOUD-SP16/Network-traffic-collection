import time
from influxdb import InfluxDBClient
from entropy import entropy_calc
import re

def predict_mal(zeus, crypto_exploit, ponmo):

    results = []
    # MALICIOUS DOMAIN SECTION
    zeuslist = list(zeus.get_points(measurement='http'))
    for z in zeuslist:
        ent = entropy_calc.sentropy(z['Domain'].split(".")[0])
        if ( ent > 2.921928094887362 and ent < 3.7735572622751845):
            results.append(CreateBatchMal(z, 'Zeus'))

    # MALICIOUS GET OR POST
    celist = list(crypto_exploit.get_points(measurement='http'))
    for c in celist:
        if c['action'] == 'GET':
            if("?" in c['URL']):
                # check randomness of string parameter in URL
                ent = entropy_calc.sentropy(c['URL'].split("?")[1])
                if (ent > 2.921928094887362 and ent < 3.7735572622751845):
                    results.append(CreateBatchMal(c, 'Exploit Kit',0.0))
        if c['action'] == 'POST':
            if ("=" in c['URL']):
                # check randomness of string parameter in URL
                ent = entropy_calc.sentropy(c['URL'].split("=")[1])
                if (ent > 2.921928094887362 and ent < 3.7735572622751845):
                    results.append(CreateBatchMal(c, 'Cryptowall',0.0))

    # MALICIOUS PERIODIC GET REQUEST DETECTOR
    ponlist= list(ponmo.get_points(measurement='http'))
    timelist = []

    # extract time from suspicious requests, check periodicity
    for p in ponlist:
        alltime = re.split(":",p['time'])
        mins = int(alltime[1])
        msecs = int(alltime[2].split(".")[1].replace("Z",''))
        secs = int(alltime[2].split(".")[0])
        timelist.append(float((msecs/1000)+(secs)+(mins/60)))
    period = checkperiod(timelist)

    # add to result array with suspected period
    for p in ponlist:
        results.append(CreateBatchMal(p, 'Ponmocup',period))

    return results

# for checking periodicity of an array of times for each suspicious request (I think...)
def checkperiod(times):
    periods = sorted(times)
    interv = len(periods)
    diffs = []
    for x in range(0, interv - 1):
        diffs.append(periods[x + 1] - periods[x])
    # dictionary that contains frequencies of time differences:
    d = {x: diffs.count(x) for x in diffs}
    # find highest frequency period
    for q in range(0, len(d) - 1):
        if (d.values()[q] == max(d.values())):
            period = d.keys()[q]
    return period

# FOR WRITING RESULTS TO DB
def CreateBatchMal(X,maltype,period):
    dict_field = {
        "measurement": "http",
        "tags": {
            'URL': X['URL'],
            'action': X['action'],
            'mal_type': maltype,
            'request_tmstmp': X['time'],
        },
        'time': int(time.time()),
        "fields": {
            "value": period
        }
    }
    return dict_field

def detect(runs,host,port):

    results = []
    # ZEUS malicious traffic detection (by looking at Domain)
    # Cryptowall malicious POST request detection (by looking at URL)
    # Exploit Kit malicious GET request detection (by looking at URL)
    # Ponmuocup periodic malicious GET request detection (by looking at URL)

    # connect to current traffic DB:
    client = InfluxDBClient(host, port, database="Traffic_{}".format(runs))

    # query
    zeus = client.query("select * from http where Domain =~ /[a-z0-9]{32,48}.(info|biz|ru|com|org|net)/")
    crypto_exploit = client.query("select * from http where (URL =~ /.\.php.*?./ and action = 'POST') or (URL =~ /^[0-9][0-9]\.[0-9][0-9]\.[0-9][0-9][0-9]\.[0-9][0-9][0-9]\/^?/ and action = 'GET')")
    ponmo = client.query("SELECT * FROM http WHERE URL =~ /\/complete.search/ and action = 'GET'")

    # analyze
    results = predict_mal(zeus, crypto_exploit, ponmo)

    # write analysis results to DB
    client = InfluxDBClient(host, port, database="Detect_{}".format(runs))
    client.create_database('Detect_{}'.format(runs))

    client.write_points(results)































