# Geoip2Influx

A docker mod for the linuxserver/letsencrypt container adding a python script to send geo location metrics to InfluxDB

### NOTE: Still under development!

Adapted source: https://github.com/ratibor78/geostat

![](https://i.imgur.com/fYyPIZ2.png)

The mod will parse the access log for IPs and and convert them into geo metrics for InfluxDB it will also send log metrics in enabled.

Add `-e DOCKER_MODS=gilbn/lsio-docker-mods:geoip2-nginx-stats`

## Enviroment variables:

These are the default values for all envs. 
Add the ones that differ on your system. 
```
-e GEOIP_DB_PATH=/config/geoip2db/GeoLite2-City.mmdb
-e NGINX_LOG_PATH=/config/log/nginx/access.log
-e INFLUX_HOST=localhost
-e INFLUX_HOST_PORT=8086
-e INFLUX_DATABASE=geoip2influx
-e INFLUX_USER=root
-e INFLUX_PASS=root
-e GEO_MEASUREMENT=geoip2influx
-e LOG_MEASUREMENT=nginx_access_logs
-e SEND_NGINX_LOGS=true
-e GEOIP2_KEY=
 ```
If `-e GEOIP2_KEY`is blank it will skip downloading the database.

The database will be created automatically.
 
Temporary grafana dashboard: https://gist.github.com/gilbN/e7137df65b7e33dba4f762e5c57ffcf4
