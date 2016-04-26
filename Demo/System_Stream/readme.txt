To run this program:

FIRST: 
Enter this folder's directory and run the following command:
"sudo python perf_test.py N"
Where N is the number of requests you wish to stream and wait for Tcpdump to collect.

THEN:
Enable whatever HTTP traffic generator you are using to test this program. We used Tsung, please refer to our documentation for more information.

It is important that these steps occur in this particular order, so that the second part begins after Tcpdump begins to collect packets.
