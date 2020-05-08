import re
import os
from datetime import datetime
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
