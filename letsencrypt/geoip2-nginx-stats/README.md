# Geoip2Influx

A docker mod for the linuxserver/letsencrypt container adding a python script to send geo location metrics to InfluxDB

Adapted source: https://github.com/ratibor78/geostat

![](https://i.imgur.com/0aEhARP.jpg)

The mod will parse the access log for IPs and and convert them into geo metrics for InfluxDB. It will also send log metrics in enabled.

Add `-e DOCKER_MODS=gilbn/lsio-docker-mods:geoip2-nginx-stats`

## Enviroment variables:

These are the **default** values for all envs. 
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

## Grafana dashboard: 
[https://grafana.com/grafana/dashboards/12268/](https://grafana.com/grafana/dashboards/12268/)

## Sending Nginx log metrics

1. Add the following to the http block in your `nginx.conf`file:

```nginx
geoip2 /config/geolite2/GeoLite2-City.mmdb {
auto_reload 5m;
$geoip2_data_country_code country iso_code;
$geoip2_data_city_name city names en;
}

log_format custom '$remote_addr - $remote_user [$time_local]'
           '"$request" $status $body_bytes_sent'
           '"$http_referer" "$http_user_agent"'
           '"$request_time" "$upstream_connect_time"';
           '"$geoip2_data_city_name" "$geoip2_data_country_code"';
 ```
 
 2. Set the access log use the `custom` log format. 
 ```nginx
 access_log /config/log/nginx/access.log custom;
 ```
