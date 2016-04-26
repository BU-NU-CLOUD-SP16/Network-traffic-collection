import time
import math
import sys
from sets import Set
from statistics import variance
from influxdb import InfluxDBClient
import ciso8601


if __name__ == "__main__":

    def detect():
        # NUMBER OF REQUESTS FROM USER INPUT
        arglist = sys.argv
        N = int(arglist[1])
        # SHANNON CHARACTER ENTROPY CALCULATOR
        # source for equation: http://code.activestate.com/recipes/577476-shannon-entropy-calculation/

    def sentropy(str):
        stList = list(str)
        alphabet = list(Set(stList))  # list of symbols in the string
        # calculate the frequency of each symbol in the string
        freqList = []
        for symbol in alphabet:
            ctr = 0
            for sym in stList:
                if sym == symbol:
                    ctr += 1
            freqList.append(float(ctr) / len(stList))
        # Shannon entropy
        ent = 0.0
        for freq in freqList:
            ent = ent + freq * math.log(freq, 2)
        ent = -ent
        return (ent)

        # PERIODICITY DETECTOR
    def checkperiod(times,avar):
        periods = sorted(times)
        interv = len(periods)
        diffs = []
        for x in range(1, interv - 1):
            diffs.append(periods[x + 1] - periods[x])
        # Remove outliers
        for k in range(0, len(diffs)):
            if k == 0:
                last = diffs[k]
            else:
                thisdiff = diffs[k] - last
                last = diffs[k]
                if thisdiff >= 25:
                    del diffs[k]
        # Check if variance is within the desired threshhold
        if len(diffs) >= 2:
            var = variance(diffs)
            if isclose(var, avar) or var < avar:
                return True
            else:
                return False
        else:
            return False

    # FOR CHECKING EQUALITY OF FLOATS (old python)
    def isclose(a, b, rel_tol=1e-09, abs_tol=0.0):
        return abs(a - b) <= max(rel_tol * max(abs(a), abs(b)), abs_tol)

    # FOR WRITING RESULTS TO DB
    def CreateBatchMal(X,maltype):
        dict_field = {
            "measurement": "http",
            "tags": {
                'URL': X['URL'],
                'dIP': X['dIP'],
                'sIP': X['sIP'],
                'action': X['action'],
                 'mal_type': maltype,
             },
            'time': X['time'],
            "fields":{
                "value": 0.00
            }
        }
        return dict_field

    #####################################################################################################

    # NUMBER OF REQUESTS FROM USER INPUT
    # NUMBER OF REQUESTS FROM USER INPUT
    arglist = str(sys.argv[1])
    N = int(arglist)

    t1 = t2 = latency = 0

    # CONNECT TO TRAFFIC DB TO QUERY
    client = InfluxDBClient('127.0.0.1', '8086', database="Traffic_{}".format(N),username='monitor',password='monitor')

    # START TIMER
    t1 = time.time()
    # ALL QUERIES HERE
    zeus = client.query("select * from http where Domain =~ /[a-z0-9]{32,48}.(info|biz|ru|com|org|net)/")
    crypto_exploit = client.query("select * from http where (URL =~ /.\.php.*?./ and action = 'POST') or (URL =~ /^[0-9][0-9]\.[0-9][0-9]\.[0-9][0-9][0-9]\.[0-9][0-9][0-9]\/^?/ and action = 'GET')")
    ponmo = client.query("select * FROM http WHERE URL =~ /\/complete.search\?client=heirloom/ and action = 'GET'")
    cryptolocker = client.query("select * from http where Domain =~ /[a-z0-9]{13}.(.*?)/")
    alinapost = client.query("select * FROM http WHERE URL =~ /\/adobe\/version_check.php/ and action = 'POST'")
    keylogger_seq1 = client.query("select * FROM http WHERE URL =~ /\/s\?gs_rn=16&gs_ri=psy\-ab&suggest=p&cp=/ and action = 'GET'")
    keylogger_seq2 = client.query("select * FROM http WHERE URL =~ /\/complete\/search\?client=hp&hl=en&gs_rn=16&gs_ri=psy\-ab&suggest=p&cp/ and action = 'GET'")
    darkness = client.query("select * FROM http WHERE URL =~ /\/index\.php\?uid=587609&ver=8g/ and action = 'GET'")
    kuluoz = client.query("select * from http where URL =~ /\/C338D6D09CA45230980EF28CDAEF57A1E80E725685E70E5ED4088FFB98E21ECC52E0A6FB44B8C30DEA90454BD8E292E523BE43AE9871A36910BACBD3E09B23700FDE12BC8A5F54E0FB8BDC91E6D5B4/ and action = 'GET'")

    # analyze
    results = []

    #################################################################################################
    # MALICIOUS DOMAIN SECTION
    zeuslist = list(zeus.get_points(measurement='http'))
    for z in zeuslist:
        ent = sentropy(z['Domain'].split(".")[0])
        if (ent >= 4.2195282823 and ent <= 4.55305590733 or isclose(ent,4.2195282823) or isclose(ent,4.55305590733)):
            results.append(CreateBatchMal(z, 'Zeus'))

    #################################################################################################
    # MALICIOUS GET OR POST
    celist = list(crypto_exploit.get_points(measurement='http'))
    for c in celist:
        if c['action'] == 'GET':
            if ("?" in c['URL']):
            # check randomness of string parameter in URL
                ent = sentropy(c['URL'].split("?")[1])
                if (ent >= 2.921928094887362 and ent <= 3.7735572622751845 or isclose(ent,2.921928094887362) or isclose(ent,3.7735572622751845)):
                    results.append(CreateBatchMal(c, 'Exploit Kit'))
        if c['action'] == 'POST':
            if ("=" in c['URL']):
                # check randomness of string parameter in URL
                ent = sentropy(c['URL'].split("=")[1])
                if (ent >= 2.921928094887362 and ent <= 3.7735572622751845 or isclose(ent,2.921928094887362) or isclose(ent,3.7735572622751845)):
                    results.append(CreateBatchMal(c, 'Cryptowall'))

    #################################################################################################
    # MALICIOUS GET REQUEST DETECTOR FOR PONMOCUP
    ponlist = list(ponmo.get_points(measurement='http'))
    for p in ponlist:
        results.append(CreateBatchMal(p, 'Ponmocup'))

    #################################################################################################
    # MALICIOUS DNS REQUEST DETECTOR (CRYPTOLOCKER)
    cryptolist = list(cryptolocker.get_points(measurement='http'))
    for c in cryptolist:
        ent = sentropy(c['Domain'].split(".")[0])
        if (ent >= 3.08505510276 and ent <= 3.3232314288):
            results.append(CreateBatchMal(c, 'CryptoLocker'))

    #################################################################################################
    # PERIODIC MALICIOUS POST TRAFFIC DETECTOR
    alinalist = list(alinapost.get_points(measurement='http'))
    timelist = []
    for a in alinalist:
        t = a['time']
        ts = ciso8601.parse_datetime(t)
        # to get time in us:
        timelist.append(float(time.mktime(ts.timetuple()) + 1e-6 * ts.microsecond))

    # check periodicity
    checkalina = checkperiod(timelist,0.030604491454)
    if checkalina is True:
        for a in alinalist:
            results.append(CreateBatchMal(a, 'Alina_Periodic_Post'))

    # MALICIOUS KEYLOGGER GET SEQUENCE DETECTOR
    keylist1 = list(keylogger_seq1.get_points(measurement='http'))
    keylist2 = list(keylogger_seq2.get_points(measurement='http'))
    timelist1 = []
    timelist2 = []
    allseqs = len(keylist1)

    #extract timestamps from first list
    for k1 in keylist1:
        t = k1['time']
        ts = ciso8601.parse_datetime(t)
        # to get time in us:
        timelist1.append(float(time.mktime(ts.timetuple()) + 1e-6 * ts.microsecond))

    #extract timestamps from second list
    for k2 in keylist1:
        t = k2['time']
        ts = ciso8601.parse_datetime(t)
        # to get time in us:
        timelist2.append(float(time.mktime(ts.timetuple()) + 1e-6 * ts.microsecond))

    #check time differences
    for x in range(0,allseqs-1):
        if timelist2[x] - timelist1[x] <= .2:
            results.append(CreateBatchMal(keylist1[x], 'Keylogger'))
            results.append(CreateBatchMal(keylist2[x], 'Keylogger'))
    #################################################################################################
    # DARKNESS DDOS MALICIOUS GET TRAFFIC DETECTOR
    darklist = list(darkness.get_points(measurement='http'))
    timelistd = []
    outlierd = []
    for d in darklist:
        t = d['time']
        ts = ciso8601.parse_datetime(t)
        # to get time in us:
        timelistd.append(float(time.mktime(ts.timetuple()) + 1e-6 * ts.microsecond))
    # check periodicity
    checkdark = checkperiod(timelistd, 0.0134380314051)
    if checkdark is True:
        for d in darklist:
            results.append(CreateBatchMal(d, 'Darkness'))

    ##################################################################################################
    # KULUOZ PERIODIC MALICIOUS GET cCOMMUNICATION
    kullist = list(kuluoz.get_points(measurement='http'))
    timelistk = []
    outlierk = []
    for k in kullist:
        t = k['time']
        ts = ciso8601.parse_datetime(t)
        # to get time in us:
        timelistk.append(float(time.mktime(ts.timetuple()) + 1e-6 * ts.microsecond))
    # check periodicity
    checkkulu = checkperiod(timelistk, 1.346600235)
    if checkkulu is True:
        for k in kullist:
            results.append(CreateBatchMal(k, 'Kuluoz'))
    ##################################################################################################

    # CONNECT TO DETECTION DB
    client = InfluxDBClient('127.0.0.1', '8086', database="Detect_{}".format(N),username='grafana',password='grafana')

    # CHECK EXISTENCE OF DATABASE
    alldbs = client.get_list_database()
    checkdb = False
    for a in alldbs:
        if a['name'] == "Detect_{}".format(N):
            checkdb = True
        if checkdb == False:
            client.create_database("Detect_{}".format(N))
    # WRITE ALL RESULTS
    client.write_points(results,time_precision='u')

    # STOP TIMER
    t2 = time.time()
    latency = float((t2 - t1)/N)

    # GOING TO STDOUT
    print(latency)
