# Geoip2Influx

<p align="center"></a>

<a href="https://discord.gg/HSPa4cz" rel="noopener"><img class="alignnone" title="Geoip2Influx!" src="https://img.shields.io/badge/chat-Discord-blue.svg?style=for-the-badge&logo=discord" alt="" height="37" />
</a>
<a href="https://technicalramblings.com/" rel="noopener"><img class="alignnone" title="technicalramblings!" src="https://img.shields.io/badge/blog-technicalramblings.com-informational.svg?style=for-the-badge" alt="" height="37" />
</a>
<a href="https://hub.docker.com/r/gilbn/lsio-docker-mods" rel="noopener"><img alt="Docker Cloud Build Status" src="https://img.shields.io/docker/cloud/build/gilbn/lsio-docker-mods?style=for-the-badge&logo=docker" height="37">
</a>
<br />
<br />

A docker mod for the linuxserver/letsencrypt container adding a python script to send geo location metrics to InfluxDB

Adapted source: https://github.com/ratibor78/geostat

![](https://i.imgur.com/mh0IhYA.jpg)

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
-e INFLUX_RETENTION=30d
-e INFLUX_SHARD=2d

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

### Multiple log files

If you separate your nginx log files but want this mod to parse all of them you can do the following:

As nginx can have multiple `access log` directives in a block, just add another one in the server block. 

**Example**

```nginx
	access_log /config/log/nginx/technicalramblings/access.log custom;
	access_log /config/log/nginx/access.log custom;
```
This will log the same lines to both files.

Then use the `/config/log/nginx/access.log` file in the `NGINX_LOG_PATH` variable. 

***

## Updates 
**06.06.20** - Added influx retention policy to try and mitigate max-values-per-tag limit exceeded errors.

  * `-e INFLUX_RETENTION` Default 30d
  * `-e INFLUX_SHARD` Default 2d
  * It will only add the retention policy if the database doesn't exist.

**30.05.20** - Added logging. Use `-e GEOIP2INFLUX_LOG_LEVEL` to set the log level.

**15.05.20** - Removed `GEOIP2_KEY` and `GEOIP_DB_PATH`variables. With commit https://github.com/linuxserver/docker-letsencrypt/commit/75b9685fdb3ec6edda590300f289b0e75dd9efd0 the letsencrypt container now natively supports downloading and updating(weekly) the GeoLite2-City database!
