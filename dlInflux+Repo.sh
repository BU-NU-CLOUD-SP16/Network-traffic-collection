mkdir workspace
cd workspace/
wget https://s3.amazonaws.com/influxdb/influxdb_0.12.1-1_amd64.deb
sudo dpkg -i influxdb_0.12.1-1_amd64.deb
sudo apt-get update && sudo apt-get install influxdb
sudo service influxdb start
curl -G http://localhost:8086/query --data-urlencode "q=CREATE DATABASE TRAFFIC"
curl -G http://localhost:8086/query --data-urlencode "q=CREATE DATABASE Detect"
mkdir NetworkTrafficCollection
git clone https://github.com/BU-NU-CLOUD-SP16/Network-traffic-collection.git NetworkTrafficCollection
