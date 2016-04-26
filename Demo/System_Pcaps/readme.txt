This version of the program that runs on the vRouter reads traffic from the Pcap files stored in the "testing" folder and stores malicious detection results in a seperate database. 
In order to run this program:

1) Enter the testing folder: Untar sample9.pcap and erase the tar file.
2) Go to http://www.malware-traffic-analysis.net/2015/07/24/index.html , download sample2.pcap, and place in this folder (it was too big for github)
3) Enter the config.txt file, replace * with the directory that leads to the inside of the testing folder, so that the program knows where the pcaps it will parse are located. Make sure that the pcap file names are formatted in the following manner: "sample#.pcap" , where # is replaced by a number.
4) Run the following command: sudo python system.py
5) Go to localhost:8083 and observe the detection results!
(A sample screenshot of the deetection results is in this folder, named "sample.png")
