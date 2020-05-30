# Geoip2Influx

A docker mod for the linuxserver/letsencrypt container adding a python script to send geo location metrics to InfluxDB

Adapted source: https://github.com/ratibor78/geostat

![](https://i.imgur.com/faAtc4U.png)

The mod will parse the access log for IPs and and convert them into geo metrics for InfluxDB. It will also send log metrics if enabled.

Add `-e DOCKER_MODS=gilbn/lsio-docker-mods:geoip2-nginx-stats`

## Enviroment variables:

These are the **default** values for all envs. 
Add the ones that differ on your system. 
```
-e NGINX_LOG_PATH=/config/log/nginx/access.log \
-e INFLUX_HOST=localhost \
-e INFLUX_HOST_PORT=8086 \
-e INFLUX_DATABASE=geoip2influx \
-e INFLUX_USER=root \
-e INFLUX_PASS=root \
-e GEO_MEASUREMENT=geoip2influx \ # InfluxDB measurement name for geohashes
-e LOG_MEASUREMENT=nginx_access_logs \ # InfluxDB measurement name for nginx logs
-e SEND_NGINX_LOGS=true \
-e GEOIP2INFLUX_LOG_LEVEL=INFO \ # Set to debug for debugging..

 ```
### MaxMind Geolite2

Use: 
```
-e MAXMINDDB_LICENSE_KEY=<license-key>
```
Default download location is `/config/geoip2db/GeoLite2-City.mmdb`

### InfluxDB 

The InfluxDB database will be created automatically with the name you choose.

```
-e INFLUX_DATABASE=geoip2influx 
```

## Grafana dashboard: 
### [Grafana Dashboard Link](https://grafana.com/grafana/dashboards/12268/)

### Sending Nginx log metrics

1. Add the following to the http block in your `nginx.conf`file:

```nginx
geoip2 /config/geoip2db/GeoLite2-City.mmdb {
auto_reload 5m;
$geoip2_data_country_code country iso_code;
$geoip2_data_city_name city names en;
}

log_format custom '$remote_addr - $remote_user [$time_local]'
           '"$request" $status $body_bytes_sent'
           '"$http_referer" "$http_user_agent"'
           '"$request_time" "$upstream_connect_time"'
           '"$geoip2_data_city_name" "$geoip2_data_country_code"';
 ```
 
 2. Set the access log use the `custom` log format. 
 ```nginx
 access_log /config/log/nginx/access.log custom;
 ```

#### Updates 
30.05.20 - Added logging. Use `-e GEOIP2INFLUX_LOG_LEVEL` to set the log level.

15.05.20 - Removed `GEOIP2_KEY` and `GEOIP_DB_PATH`variables. With commit https://github.com/linuxserver/docker-letsencrypt/commit/75b9685fdb3ec6edda590300f289b0e75dd9efd0 the letsencrypt container now natively supports downloading and updating(weekly) the GeoLite2-City database!
