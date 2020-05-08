#! /usr/bin/env python3

# Getting GEO information from Nginx access.log by IP's.
# Alexey Nizhegolenko 2018
# Parts added by Remko Lodder, 2019.
# Added: IPv6 matching, make query based on geoip2 instead of
# geoip, which is going away r.s.n.
# GilbN 2020: Adapted to Python 3 and changed config to use enviroment variables.
# And added more metrics.

import os
import re
import sys
import time
import geoip2.database
import geohash2
from influxdb import InfluxDBClient
from IPy import IP as ipadd
from datetime import datetime

def logparse(LOGPATH, INFLUXHOST, INFLUXPORT, INFLUXDBDB, INFLUXUSER, INFLUXUSERPASS, MEASUREMENT, LOG_MEASUREMENT, GEOIPDB, INODE): # NOQA
    # Preparing variables and params
    IPS = {}
    COUNT = {}
    GEOHASH = {}
    LOG_DATA = {}
    NGINX_LOG = {}
    HOSTNAME = os.uname()[1]
    CLIENT = InfluxDBClient(host=INFLUXHOST, port=INFLUXPORT,
                            username=INFLUXUSER, password=INFLUXUSERPASS, database=INFLUXDBDB) # NOQA

    re_IPV4 = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
    re_IPV6 = re.compile(r'(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))') # NOQA
    #IPV4 = re.compile(r'(?P<ipaddress>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - (?P<remote_user>.+) \[(?P<dateandtime>\d{2}\/[A-Z]{1}[a-z]{2}\/\d{4}:\d{2}:\d{2}:\d{2} ((\+|\-)\d{4})\])(["](?P<method>[A-Z]{1,7})) (?P<refferer>.+) ((?P<http_version>HTTP\/[1-3]\.[0-9])["]) (?P<status_code>\d{3}) (?P<bytes_sent>\d{1,99})(["](?P<url>(\-)|(.+))["]) (["](?P<user_agent>.+)["])(["](?P<request_time>.+)["]) (["](?P<connect_time>.+)["])(["](?P<city>.+)["]) (["](?P<country_code>.+)["])', re.IGNORECASE)
    #IPV6 = re.compile(r'(?P<ipaddress>(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))) - (?P<remote_user>.+) \[(?P<dateandtime>\d{2}\/[A-Z]{1}[a-z]{2}\/\d{4}:\d{2}:\d{2}:\d{2} ((\+|\-)\d{4})\])(["](?P<method>[A-Z]{1,7})) (?P<refferer>.+) ((?P<http_version>HTTP\/[1-3]\.[0-9])["]) (?P<status_code>\d{3}) (?P<bytes_sent>\d{1,99})(["](?P<url>(\-)|(.+))["]) (["](?P<user_agent>.+)["])(["](?P<request_time>.+)["]) (["](?P<connect_time>.+)["])(["](?P<city>.+)["]) (["](?P<country_code>.+)["])', re.IGNORECASE)
    IPV4 = re.compile(r'(?P<ipaddress>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - (?P<remote_user>.+) \[(?P<dateandtime>\d{2}\/[A-Z]{1}[a-z]{2}\/\d{4}:\d{2}:\d{2}:\d{2} ((\+|\-)\d{4}))\](["](?P<method>[A-Z]{1,7})) (?P<refferer>.+) ((?P<http_version>HTTP\/[1-3]\.[0-9])["]) (?P<status_code>\d{3}) (?P<bytes_sent>\d{1,99})(["](?P<url>(\-)|(.+))["]) (["](?P<user_agent>.+)["])(["](?P<request_time>.+)["]) (["](?P<connect_time>.+)["])(["](?P<city>.+)["]) (["](?P<country_code>.+)["])', re.IGNORECASE)
    IPV6 = re.compile(r'(?P<ipaddress>(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))) - (?P<remote_user>.+) \[(?P<dateandtime>\d{2}\/[A-Z]{1}[a-z]{2}\/\d{4}:\d{2}:\d{2}:\d{2} ((\+|\-)\d{4}))\](["](?P<method>[A-Z]{1,7})) (?P<refferer>.+) ((?P<http_version>HTTP\/[1-3]\.[0-9])["]) (?P<status_code>\d{3}) (?P<bytes_sent>\d{1,99})(["](?P<url>(\-)|(.+))["]) (["](?P<user_agent>.+)["])(["](?P<request_time>.+)["]) (["](?P<connect_time>.+)["])(["](?P<city>.+)["]) (["](?P<country_code>.+)["])', re.IGNORECASE)
    
    GI = geoip2.database.Reader(GEOIPDB)

    # Main loop to parse access.log file in tailf style with sending metrcs
    with open(LOGPATH, "r") as FILE:
        print("starter main loop")
        STR_RESULTS = os.stat(LOGPATH)
        ST_SIZE = STR_RESULTS[6]
        FILE.seek(ST_SIZE)
        while True:
            print("true")
            METRICS = []
            WHERE = FILE.tell()
            LINE = FILE.readline()
            INODENEW = os.stat(LOGPATH).st_ino
            if INODE != INODENEW:
                break
            if not LINE:
                time.sleep(1)
                FILE.seek(WHERE)
            else:
                if re_IPV4.match(LINE):
                    m = re_IPV4.match(LINE)
                    IP = m.group(1)
                    lineformat = IPV4
                elif re_IPV6.match(LINE):
                    m = re_IPV6.match(LINE)
                    IP = m.group(1)
                    lineformat = IPV6

                if ipadd(IP).iptype() == 'PUBLIC' and IP:
                    print("geohash if loop")
                    INFO = GI.city(IP)
                    if INFO is not None:
                        print("starter geohash")
                        HASH = geohash2.encode(INFO.location.latitude, INFO.location.longitude) # NOQA
                        COUNT['count'] = 1
                        GEOHASH['geohash'] = HASH
                        GEOHASH['host'] = HOSTNAME
                        GEOHASH['country_code'] = INFO.country.iso_code
                        GEOHASH['country_name'] = INFO.country.name
                        GEOHASH['state'] = INFO.subdivisions.most_specific.name
                        GEOHASH['state_code'] = INFO.subdivisions.most_specific.iso_code
                        GEOHASH['city'] = INFO.city.name
                        GEOHASH['postal_code'] = INFO.postal.code
                        GEOHASH['latitude'] = INFO.location.latitude
                        GEOHASH['longitude'] = INFO.location.longitude
                        IPS['tags'] = GEOHASH
                        IPS['fields'] = COUNT
                        IPS['measurement'] = MEASUREMENT
                        METRICS.append(IPS)
                        print("sender geohashdata")
                        # Sending json data to InfluxDB
                        #CLIENT.write_points(METRICS)
                        time.sleep(5)
                        print("ferdig")
            

                for l in LINE:
                    print("starting logg for loop")
                    data = re.search(lineformat, l) 
                    try:         
                        datadict = data.groupdict()
                    except AttributeError as e:
                        print(e)
                        continue
                    COUNT['count'] = 1
                    LOG_DATA['IP'] = datadict["ipaddress"]
                    LOG_DATA['datetime'] = datetime.strptime(datadict["dateandtime"], "%d/%b/%Y:%H:%M:%S %z")
                    LOG_DATA['remote_user'] = datadict["remote_user"]
                    LOG_DATA['method'] = datadict["method"]
                    LOG_DATA['refferer'] = datadict["refferer"]
                    LOG_DATA['http_version'] = datadict["http_version"]
                    LOG_DATA['status_code'] = datadict["status_code"]
                    LOG_DATA['bytes_sent'] = datadict["bytes_sent"]
                    LOG_DATA['url'] = datadict["url"]
                    LOG_DATA['user_agent'] = datadict["user_agent"]
                    LOG_DATA['request_time'] = datadict["request_time"]
                    LOG_DATA['connect_time'] = datadict["connect_time"]
                    LOG_DATA['city'] = datadict["city"]
                    LOG_DATA["country_code"] = datadict["country_code"]
                    NGINX_LOG['tags'] = LOG_DATA
                    NGINX_LOG['fields'] = COUNT
                    NGINX_LOG['measurement'] = LOG_MEASUREMENT
                    METRICS.append(NGINX_LOG)
                    print("sender log stats")
                    CLIENT.write_points(METRICS)
                    print("ferdig")
                    time.sleep(5)
                        

def main():
    # Getting params from envs
    GEOIPDB = os.getenv('GEOIP_DB_PATH', '/home/marius/Documents/log/GeoLite2-City.mmdb')
    LOGPATH = os.getenv('NGINX_LOG_PATH', '/home/marius/Documents/log/nginx.log')
    INFLUXHOST = os.getenv('INFLUX_HOST', '192.168.1.34')
    INFLUXPORT = os.getenv('INFLUX_HOST_PORT', '8082')
    INFLUXDBDB = os.getenv('INFLUX_DATABASE', 'test')
    INFLUXUSER = os.getenv('INFLUX_USER', 'root')
    INFLUXUSERPASS = os.getenv('INFLUX_PASS', 'root')
    MEASUREMENT = os.getenv('MEASUREMENT', 'geoip2influx')
    LOG_MEASUREMENT = os.getenv('LOG_MEASUREMENT','nginx_access_logs')

    # Parsing log file and sending metrics to Influxdb
    while True:
        # Get inode from log file
        INODE = os.stat(LOGPATH).st_ino
        # Run main loop and grep a log file
        if os.path.exists(LOGPATH):
            logparse(LOGPATH, INFLUXHOST, INFLUXPORT, INFLUXDBDB, INFLUXUSER, INFLUXUSERPASS, MEASUREMENT, LOG_MEASUREMENT, GEOIPDB, INODE) # NOQA
        else:
            print(('File %s not found' % LOGPATH))


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)



#lineformat = re.compile(r"""(?P<ipaddress>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - (?P<remote_user>.+) \[(?P<dateandtime>\d{2}\/[A-Z]{1}[a-z]{2}\/\d{4}:\d{2}:\d{2}:\d{2} ((\+|\-)\d{4})\])(["](?P<method>.+)) (?P<refferer>.+) (?P<http_version>HTTP\/[1-3]\.[0-9]") (?P<status_code>\d{3}) (?P<bytes_sent>\d+) (["](?P<url>(\-)|(.+))["]) (["](?P<user_agent>.+)["])(["](?P<request_time>.+)["]) (["](?P<connect_time>.+)["]) (["](?P<city>.+)["]) (["](?P<country_code>.+)["])""", re.IGNORECASE)
#INPUT_DIR = "log"
#ipv6 = re.compile(r'(?P<ipv6>(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])))', re.IGNORECASE)

#lineformat = re.compile(r"""(?P<ipaddress>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""", re.IGNORECASE)

#path = "./log/nginx.log"
#logfile =  open(path,"r")

def test():
    #lineformat = re.compile(r"""(?P<ipaddress>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - (?P<remote_user>.+) \[(?P<dateandtime>\d{2}\/[A-Z]{1}[a-z]{2}\/\d{4}:\d{2}:\d{2}:\d{2} ((\+|\-)\d{4})\])(["](?P<method>[A-Z]{3})) (?P<refferer>.+) (?P<http_version>HTTP\/[1-3]\.[0-9]") (?P<status_code>\d{3}) (?P<bytes_sent>\d+) (["](?P<url>(\-)|(.+))["]) (["](?P<user_agent>.+)["])(["](?P<request_time>.+)["]) (["](?P<connect_time>.+)["]) (["](?P<city>.+)["]) (["](?P<country_code>.+)["])""", re.IGNORECASE)
    lineformat = re.compile(r'(?P<ipaddress>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - (?P<remote_user>.+) \[(?P<dateandtime>\d{2}\/[A-Z]{1}[a-z]{2}\/\d{4}:\d{2}:\d{2}:\d{2} ((\+|\-)\d{4}))\](["](?P<method>[A-Z]{1,7})) (?P<refferer>.+) ((?P<http_version>HTTP\/[1-3]\.[0-9])["]) (?P<status_code>\d{3}) (?P<bytes_sent>\d{1,99})(["](?P<url>(\-)|(.+))["]) (["](?P<user_agent>.+)["])(["](?P<request_time>.+)["]) (["](?P<connect_time>.+)["])(["](?P<city>.+)["]) (["](?P<country_code>.+)["])', re.IGNORECASE)
    #IPV6_lineformat = re.compile(r'(?P<ipaddress>(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))) - (?P<remote_user>.+) \[(?P<dateandtime>\d{2}\/[A-Z]{1}[a-z]{2}\/\d{4}:\d{2}:\d{2}:\d{2} ((\+|\-)\d{4}))\](["](?P<method>[A-Z]{1,7})) (?P<refferer>.+) ((?P<http_version>HTTP\/[1-3]\.[0-9])["]) (?P<status_code>\d{3}) (?P<bytes_sent>\d{1,99})(["](?P<url>(\-)|(.+))["]) (["](?P<user_agent>.+)["])(["](?P<request_time>.+)["]) (["](?P<connect_time>.+)["])(["](?P<city>.+)["]) (["](?P<country_code>.+)["])', re.IGNORECASE)
    path = "nginx.log"
    logfile =  open(path,"r")
    for l in logfile.readlines():
        data = re.search(lineformat, l)
        #print(data)
        COUNT = {}
        LOG_DATA = {}
        NGINX_LOG = {}
        METRICS = []
        try:
            datadict = data.groupdict()
        except AttributeError:
            continue
        data = re.search(lineformat, l) 
        try:         
            datadict = data.groupdict()
        except AttributeError as e:
            print(e)
            continue
        COUNT['count'] = 1
        LOG_DATA['IP'] = datadict["ipaddress"]
        LOG_DATA['datetime'] = datetime.strptime(datadict["dateandtime"], "%d/%b/%Y:%H:%M:%S %z")
        LOG_DATA['remote_user'] = datadict["remote_user"]
        LOG_DATA['method'] = datadict["method"]
        LOG_DATA['refferer'] = datadict["refferer"]
        LOG_DATA['http_version'] = datadict["http_version"]
        LOG_DATA['status_code'] = datadict["status_code"]
        LOG_DATA['bytes_sent'] = datadict["bytes_sent"]
        LOG_DATA['url'] = datadict["url"]
        LOG_DATA['user_agent'] = datadict["user_agent"]
        LOG_DATA['request_time'] = datadict["request_time"]
        LOG_DATA['connect_time'] = datadict["connect_time"]
        LOG_DATA['city'] = datadict["city"]
        LOG_DATA["country_code"] = datadict["country_code"]
        NGINX_LOG['tags'] = LOG_DATA
        NGINX_LOG['fields'] = COUNT
        NGINX_LOG['measurement'] = "LOG_MEASUREMENT"
        METRICS.append(NGINX_LOG)
        print("sender log stats")
        print(METRICS)
        print("ferdig")






        try:
            ip = datadict["ipaddress"]
            #datetimestring = datadict["dateandtime"]
            datetimeobj = datetime.strptime(datadict["dateandtime"], "%d/%b/%Y:%H:%M:%S %z")
            remote_user = datadict["remote_user"]
            datetimestring = datadict["dateandtime"]
            method = datadict["method"]
            refferer = datadict["refferer"]
            http_version = datadict["http_version"]
            status_code = datadict["status_code"]
            bytes_sent = datadict["bytes_sent"]
            url = datadict["url"]
            user_agent = datadict["user_agent"]
            request_time = datadict["request_time"]
            connect_time = datadict["connect_time"]
            city = datadict["city"]
            country_code = datadict["country_code"]
            print(datetimeobj)
            #print( "IP: " + ip + "DATE: " + datetimestring + "REMOTE USER: " + remote_user + " " + "METHOD: " + method + " "+"REFF: " + ref+" "+ "HTTP VERSION: "+http_version)
        except AttributeError:
            continue
        logfile.close()

for f in os.listdir(INPUT_DIR):
    logfile = open(os.path.join(INPUT_DIR, f))

    for l in logfile.readlines():
        data = re.search(lineformat, l)
        if data:
            datadict = data.groupdict()
            ip = datadict["ipaddress"]
            remote_user = datadict["remote_user"]
            datetimestring = datadict["dateandtime"]
            method = datadict["method"]
            refferer = datadict["refferer"]
            http_version = datadict["http_version"]
            status_code = datadict["status_code"]
            bytes_sent = datadict["bytes_sent"]
            url = datadict["url"]
            user_agent = datadict["user_agent"]
            request_time = datadict["request_time"]
            connect_time = datadict["connect_time"]
            city = datadict["city"]
            country_code = datadict["country_code"]


    logfile.close()