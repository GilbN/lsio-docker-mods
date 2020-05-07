# Geoip2Influx

A docker mod for the linuxserver/letsencrypt container adding a python script to send geo location metrics to InfluxDB

### NOTE: Still under development!

Adapted source: https://github.com/ratibor78/geostat

The mod will parse the access log for IPs and and convert them into geo metrics for InfluxDB.

Add `-e DOCKER_MODS=gilbn/lsio-docker-mods:geoip2-nginx-stats`

## Enviroment variables:

These are the default values for all envs. 
If you have telegraf and influxdb already setup you only need to add TELEGRAF_HOST
```
-e GEOIP_DB_PATH=/config/geoip2db/GeoLite2-City.mmdb
-e NGINX_LOG_PATH=/config/log/nginx/access.log
-e INFLUX_HOST=127.0.0.1
-e INFLUX_HOST_PORT=8086
-e INFLUX_DATABASE=telegraf
-e INFLUX_USER=root
-e INFLUX_PASS=root
-e MEASUREMENT=geoip2influx
 ```
 You will need to download the Geolite2 database. (May add some variables for the licensekey and a cronjob for updating in the future)
 
See here on how to download it, and add geoblocking if you feel like it. (Not needed for this mod) https://technicalramblings.com/blog/blocking-countries-with-geolite2-using-the-letsencrypt-docker-container/
 
 Temporary grafana dashboard: https://gist.github.com/gilbN/e7137df65b7e33dba4f762e5c57ffcf4
