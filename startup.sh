#Script to start the project

#CREATE WORKPLACE
mkdir workspace 
cd workspace/

#INSTALL AND START INFLUXDB
wget https://s3.amazonaws.com/influxdb/influxdb_0.12.1-1_amd64.deb
sudo dpkg -i influxdb_0.12.1-1_amd64.deb
sudo apt-get update && sudo apt-get install influxdb
sudo service influxdb start

#CREATE DATABASE AND USER
curl -G http://localhost:8086/query --data-urlencode "q=CREATE USER RootUser WITH PASSWORD 'Griffana' WITH ALL PRIVILEGES"
curl -G http://localhost:8086/query --data-urlencode "q=CREATE DATABASE TRAFFIC"
curl -G http://localhost:8086/query --data-urlencode "q=CREATE DATABASE Detect"

#download python dependencies
sudo apt-get install numpy
sudo apt-get install sets
sudo apt-get install statistics
sudo apt-get install ciso8601
sudo apt-get install python-influxdb

#install and pull the git repo
sudo apt-get install git
mkdir NetworkTrafficCollection
git clone https://github.com/BU-NU-CLOUD-SP16/Network-traffic-collection.git NetworkTrafficCollection




