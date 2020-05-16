#! /usr/bin/env python3

# Getting GEO information from Nginx access.log by IP's.
# Alexey Nizhegolenko 2018
# Parts added by Remko Lodder, 2019.
# Added: IPv6 matching, make query based on geoip2 instead of
# geoip, which is going away r.s.n.
# GilbN 2020:
    # Adapted to Python 3.
    # Added enviroment variables for Docker. 
    # Added log metrics
    # Switched to pep8 style variables ect.
    # Adapted to geoip2.

import os
import re
import sys
import time
import datetime

import geoip2.database
import geohash2
from influxdb import InfluxDBClient
import requests.exceptions
from IPy import IP as ipadd


def regex_tester(log_path, N):
    time_out = time.time() + 60
    while True:
        assert N >= 0
        pos = N + 1
        lines = [] 
        with open(log_path) as f: 
            while len(lines) <= N: 
                try: 
                    f.seek(-pos, 2) 
                except IOError: 
                    f.seek(0) 
                    break
                finally: 
                    lines = list(f) 
                pos *= 2
        log_lines = lines[-N:] 
        for line in log_lines:
            regex = re.compile(r'(.+ "[A-Z]{2}")', re.IGNORECASE)
            if regex.match(line):
                return True
            else:
                print("Testing regex on " + log_path)
                time.sleep(2)
        if time.time() > time_out:
            break


def file_exists(log_path,geoip_db_path):
    time_out = time.time() + 30
    while True:
        if not os.path.exists(log_path):
            print(('File %s not found' % log_path))
            time.sleep(1)
        if not os.path.exists(geoip_db_path):
            print(('File %s not found' % geoip_db_path))
            time.sleep(1)
        file_list = [log_path, geoip_db_path]
        if all([os.path.isfile(f) for f in file_list]):
            return True
        if time.time() > time_out:
            print("Exiting")
            break            


def logparse(
        log_path, influxdb_host, influxdb_port, influxdb_database, influxdb_user, influxdb_user_pass, 
        geo_measurement, log_measurement, send_nginx_logs, geoip_db_path, inode):
    # Preparing variables and params
    ips = {}
    geohash_fields = {}
    geohash_tags = {}
    log_data_fields = {}
    log_data_tags = {}
    nginx_log = {}
    hostname = os.uname()[1]
    client = InfluxDBClient(
        host=influxdb_host, port=influxdb_port, username=influxdb_user, password=influxdb_user_pass, database=influxdb_database)
    try:
        client.create_database(influxdb_database)
    except requests.exceptions.ConnectionError as e:
        print(str(e) + "\n\n Unable to connect to InfluxDB!")
        sys.exit(1)
    client.switch_database(influxdb_database)
    re_ipv4 = re.compile(r'(?P<ipaddress>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - (?P<remote_user>.+) \[(?P<dateandtime>\d{2}\/[A-Z]{1}[a-z]{2}\/\d{4}:\d{2}:\d{2}:\d{2} ((\+|\-)\d{4}))\](["](?P<method>[A-Z]{1,7})) (?P<referrer>.+) ((?P<http_version>HTTP\/[1-3]\.[0-9])["]) (?P<status_code>\d{3}) (?P<bytes_sent>\d{1,99})(["](?P<url>(\-)|(.+))["]) (["](?P<user_agent>.+)["])(["](?P<request_time>.+)["]) (["](?P<connect_time>.+)["])(["](?P<city>.+)["]) (["](?P<country_code>.+)["])', re.IGNORECASE) # NOQA
    re_ipv6 = re.compile(r'(?P<ipaddress>(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))) - (?P<remote_user>.+) \[(?P<dateandtime>\d{2}\/[A-Z]{1}[a-z]{2}\/\d{4}:\d{2}:\d{2}:\d{2} ((\+|\-)\d{4}))\](["](?P<method>[A-Z]{1,7})) (?P<referrer>.+) ((?P<http_version>HTTP\/[1-3]\.[0-9])["]) (?P<status_code>\d{3}) (?P<bytes_sent>\d{1,99})(["](?P<url>(\-)|(.+))["]) (["](?P<user_agent>.+)["])(["](?P<request_time>.+)["]) (["](?P<connect_time>.+)["])(["](?P<city>.+)["]) (["](?P<country_code>.+)["])', re.IGNORECASE) # NOQA

    gi = geoip2.database.Reader(geoip_db_path)

    if send_nginx_logs in ("true", "True"):
        send_logs = True
    else:
        send_logs = False
        re_ipv4 = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
        re_ipv6 = re.compile(r'(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))') # NOQA

    if not regex_tester(log_path,3):
        if send_logs:
            re_ipv4 = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
            re_ipv6 = re.compile(r'(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))') # NOQA
            send_logs = False
            print("Regex did not match nginx logs..\nNginx log metrics disabled! \nDouble check your nginx configs..")

    # Main loop to parse access.log file in tailf style with sending metrcs
    with open(log_path, "r") as log_file:
        str_results = os.stat(log_path)
        st_size = str_results[6]
        log_file.seek(st_size)
        while True:
            geo_metrics = []
            log_metrics = []
            where = log_file.tell()
            line = log_file.readline()
            inodenew = os.stat(log_path).st_ino
            if inode != inodenew:
                break
            if not line:
                time.sleep(1)
                log_file.seek(where)
            else:
                if re_ipv4.match(line):
                    m = re_ipv4.match(line)
                    ip = m.group(1)
                    log = re_ipv4
                elif re_ipv6.match(line):
                    m = re_ipv6.match(line)
                    ip = m.group(1)
                    log = re_ipv6
                if ipadd(ip).iptype() == 'PUBLIC' and ip:
                    info = gi.city(ip)
                    if info is not None:
                        geohash = geohash2.encode(info.location.latitude, info.location.longitude) # NOQA
                        geohash_fields['count'] = 1
                        geohash_tags['geohash'] = geohash
                        geohash_tags['ip'] = ip
                        geohash_tags['host'] = hostname
                        geohash_tags['country_code'] = info.country.iso_code
                        geohash_tags['country_name'] = info.country.name
                        geohash_tags['state'] = info.subdivisions.most_specific.name
                        geohash_tags['state_code'] = info.subdivisions.most_specific.iso_code
                        geohash_tags['city'] = info.city.name
                        geohash_tags['postal_code'] = info.postal.code
                        geohash_tags['latitude'] = info.location.latitude
                        geohash_tags['longitude'] = info.location.longitude
                        ips['tags'] = geohash_tags
                        ips['fields'] = geohash_fields
                        ips['measurement'] = geo_measurement
                        geo_metrics.append(ips)
                        client.write_points(geo_metrics)
                
                if send_logs:
                    data = re.search(log, line)
                    try:         
                        datadict = data.groupdict()
                    except AttributeError as e:
                        print(e)
                        continue
                    log_data_fields['count'] = 1
                    log_data_fields['bytes_sent'] = int(datadict["bytes_sent"])
                    log_data_fields['request_time'] = float(datadict["request_time"])
                    if datadict["connect_time"] == "-":
                        log_data_fields['connect_time'] = 0.0
                    else:
                        log_data_fields['connect_time'] = float(datadict["connect_time"])
                    log_data_tags['ip'] = datadict["ipaddress"]
                    log_data_tags['datetime'] = datetime.datetime.strptime(datadict["dateandtime"], "%d/%b/%Y:%H:%M:%S %z")
                    log_data_tags['remote_user'] = datadict["remote_user"]
                    log_data_tags['method'] = datadict["method"]
                    log_data_tags['referrer'] = datadict["referrer"]
                    log_data_tags['http_version'] = datadict["http_version"]
                    log_data_tags['status_code'] = datadict["status_code"]
                    log_data_tags['bytes_sent'] = datadict["bytes_sent"]
                    log_data_tags['url'] = datadict["url"]
                    log_data_tags['user_agent'] = datadict["user_agent"]
                    log_data_tags['request_time'] = datadict["request_time"]
                    log_data_tags['connect_time'] = datadict["connect_time"]
                    log_data_tags['city'] = datadict["city"]
                    log_data_tags["country_code"] = datadict["country_code"]
                    nginx_log['tags'] = log_data_tags
                    nginx_log['fields'] = log_data_fields
                    nginx_log['measurement'] = log_measurement
                    log_metrics.append(nginx_log)
                    client.write_points(log_metrics)


def main():
    # Getting params from envs
    geoip_db_path = '/config/geoip2db/GeoLite2-City.mmdb'
    log_path = os.getenv('NGINX_LOG_PATH', '/config/log/nginx/access.log')
    influxdb_host = os.getenv('INFLUX_HOST', 'localhost')
    influxdb_port = os.getenv('INFLUX_HOST_PORT', '8086')
    influxdb_database = os.getenv('INFLUX_DATABASE', 'geoip2influx')
    influxdb_user = os.getenv('INFLUX_USER', 'root')
    influxdb_user_pass = os.getenv('INFLUX_PASS', 'root')
    geo_measurement = os.getenv('GEO_MEASUREMENT', 'geoip2influx')
    log_measurement = os.getenv('LOG_MEASUREMENT', 'nginx_access_logs')
    send_nginx_logs = os.getenv('SEND_NGINX_LOGS','true')

    # Parsing log file and sending metrics to Influxdb
    while file_exists(log_path,geoip_db_path):
        # Get inode from log file
        inode = os.stat(log_path).st_ino
        # Run main loop and grep a log file
        logparse(
            log_path, influxdb_host, influxdb_port, influxdb_database, influxdb_user, influxdb_user_pass, 
            geo_measurement, log_measurement, send_nginx_logs, geoip_db_path, inode) # NOQA

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
