import math
from sets import Set
import statistics
import re

#THIS SCRIPT IS TO CALCULATE AND PRINT THE ENTROPY THRESHHOLD FROM THE DOMAIN IN DNS BRO LOG OF MALICIOUS PCAP SAMPLE

#source for shannon entropy algorithm: http://code.activestate.com/recipes/577476-shannon-entropy-calculation/
#function for calculating shannon entropy of an input string
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
     #Shannon entropy
     ent = 0.0
     for freq in freqList:
         ent = ent + freq * math.log(freq, 2)
     ent = -ent
     return (ent)

#function for calculating the entropy threshhold
def entbounds(ents):
    #mean and standard deviation of a list of entropies for a sample of strings
    standarddev = statistics.stdev(ents)
    mean = statistics.mean(ents)
    #bounds
    lower = mean - standarddev
    upper = mean + standarddev
    minimum = min(ents)
    maximum = max(ents)
    #returns array
    return([lower,upper,minimum,maximum])


def dnsentrop(filename):
    dnsarray= []
    rows = 0
    ents=[]
    samplecount = 0
    with open(filename) as f:
        content = f.readlines()
        rows = len(content)
        for i in range(8, rows-1):
            columns = content[i].split("\t")
            request = {
                        "tags": {
                            "Timestamp":columns[0],
                            "domain":columns[8]
                        }}
            split = request["tags"]["domain"].split(".")
            sld = split[0]
            ents.append(sentropy(sld))
            samplecount += 1
    print("Number of Requests: ", samplecount, "\n")
    dnsbounds = entbounds(ents)
    print("DNS Domain Field param:\n", " Lower: ", dnsbounds[0], " Upper: ", dnsbounds[1], " Minimum: ", dnsbounds[2], " Maximum: ",dnsbounds[3])

def httpentrop(filename):
    rows = 0
    post = 0
    get = 0
    #for storing entropies
    getent = [] #for GET request parameters
    postent = [] #for POST request parameters
    samplecount = 0
    #parse http log
    with open(filename) as f:
        content = f.readlines()
        rows = len(content)
        for i in range(8, rows - 1):
            columns = content[i].split("\t")
            request = {
                "tags": {
                    "Timestamp": columns[0],
                    "method": columns[7],
                    "domain": columns[8],
                    "url": columns[9],
                }
            }
            samplecount += 1
            #parse and seperate the parameters
            method = request["tags"]["method"]
            url = request["tags"]["url"]
            #check which rule this request fits
            malpost = ("?" in url) and (method == "POST")
            malget = (("php?" in url) and (method == "GET"))
            if malpost:
                post +=1
                parameter = url.split("=")[1]
                postent.append(sentropy(parameter))
            if malget:
                get +=1
                parameter = url.split("?")[1]
                getent.append(sentropy(parameter))
    #calculate the threshhold for entropy of each kind of parameter
    print("Number of Requests: ", samplecount, "\n")
    if post is not 0 or 1:
        postbounds = entbounds(postent)
        print("POST request params:\n", " Lower: ", postbounds[0], " Upper: ", postbounds[1], " Minimum: ", postbounds[2]," Maximum: ", postbounds[3])
    if(get != 0 and get!= 1):
        getbounds = entbounds(getent)
        print("GET request params:\n", " Lower: ", getbounds[0], " Upper: ", postbounds[1], " Minimum: ", postbounds[2], " Maximum: ",postbounds[3])
