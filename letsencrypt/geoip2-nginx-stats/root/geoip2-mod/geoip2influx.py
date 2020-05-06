#! /usr/bin/env python3

# Getting GEO information from Nginx access.log by IP's.
# Alexey Nizhegolenko 2018
# Parts added by Remko Lodder, 2019.
# Added: IPv6 matching, make query based on geoip2 instead of
# geoip, which is going away r.s.n.

import os
import re
import sys
import time
import geoip2.database
import geohash2
from influxdb import InfluxDBClient
from IPy import IP as ipadd

def logparse(LOGPATH, INFLUXHOST, INFLUXPORT, INFLUXDBDB, INFLUXUSER, INFLUXUSERPASS, MEASUREMENT, GEOIPDB, INODE): # NOQA
    # Preparing variables and params
    IPS = {}
    COUNT = {}
    GEOHASH = {}
    HOSTNAME = os.uname()[1]
    CLIENT = InfluxDBClient(host=INFLUXHOST, port=INFLUXPORT,
                            username=INFLUXUSER, password=INFLUXUSERPASS, database=INFLUXDBDB) # NOQA

    re_IPV4 = re.compile('(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
    re_IPV6 = re.compile('(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))') # NOQA

    GI = geoip2.database.Reader(GEOIPDB)

    # Main loop to parse access.log file in tailf style with sending metrcs
    with open(LOGPATH, "r") as FILE:
        STR_RESULTS = os.stat(LOGPATH)
        ST_SIZE = STR_RESULTS[6]
        FILE.seek(ST_SIZE)
        while True:
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
                elif re_IPV6.match(LINE):
                    m = re_IPV6.match(LINE)
                    IP = m.group(1)

                if ipadd(IP).iptype() == 'PUBLIC' and IP:
                    INFO = GI.city(IP)
                    if INFO is not None:
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

                        # Sending json data to InfluxDB
                        CLIENT.write_points(METRICS)
                        time.sleep(10)


def main():
    # Getting params from envs
    GEOIPDB = os.getenv('GEOIP_DB_PATH', '/config/geolite2/GeoLite2-City.mmdb')
    LOGPATH = os.getenv('NGINX_LOG_PATH', '/config/log/nginx/access.log')
    INFLUXHOST = os.getenv('INFLUX_HOST', '127.0.0.1')
    INFLUXPORT = os.getenv('INFLUX_HOST_PORT', '8086')
    INFLUXDBDB = os.getenv('INFLUX_DATABASE', 'telegraf')
    INFLUXUSER = os.getenv('INFLUX_USER', 'root')
    INFLUXUSERPASS = os.getenv('INFLUX_PASS', 'root')
    MEASUREMENT = os.getenv('INFLUXDB', 'geoip2influx')

    # Parsing log file and sending metrics to Influxdb
    while True:
        # Get inode from log file
        INODE = os.stat(LOGPATH).st_ino
        # Run main loop and grep a log file
        if os.path.exists(LOGPATH):
            logparse(LOGPATH, INFLUXHOST, INFLUXPORT, INFLUXDBDB, INFLUXUSER, INFLUXUSERPASS, MEASUREMENT, GEOIPDB, INODE) # NOQA
        else:
            print(('File %s not found' % LOGPATH))


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
