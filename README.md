# ES/ELK Installation

## Preparation
```
export ES_HOST=10.10.10.20
export ES_CONFIG=/etc/elasticsearch
export ES_HTTPCERT=http.p12
export ES_KEYSTORE=elasticsearch-ca.pem
export ES_USER=elastic
export ES_PASSWD=mypass
export KIBANA_HOST
```

## ElasticSearch
1. Follow these instructions: https://www.elastic.co/guide/en/elasticsearch/reference/current/install-elasticsearch.html
2. Setup xpack security module: https://www.elastic.co/guide/en/elasticsearch/reference/current/configuring-security.html
  * (optional) setup a keystore if you want, not using it since this is a lab
3. (optional) Also need to setup TLS: https://www.elastic.co/guide/en/elasticsearch/reference/current/ssl-tls.html
4. (optional) Setup a PKCS key for encrypted comms: https://www.elastic.co/guide/en/kibana/7.9/configuring-tls.html.  Just use `bin/elasticsearch-certutil http`


DON'T START ANY OF THE FOLLOWING MODULES

## Kibana
1. Install Kibana: `apt install kibana`
2. Setup security: https://www.elastic.co/guide/en/kibana/7.9/using-kibana-with-security.html
* setup a keystore if you want, not using it since this is a lab
3. (optional) Setup TLS: https://www.elastic.co/guide/en/elasticsearch/reference/current/ssl-tls.html
4. (optional) Setup a PKCS key for encrypted comms: https://www.elastic.co/guide/en/kibana/7.9/configuring-tls.html.  Use the `http.p12` cert from before
5. If you want Kibana to be reachable by another computer, you'll need to update `server.host` in `/etc/kibana/kibana.yml` to be the IPv4 addr of the machine you on which you installed Kibana.

```
server.ssl.keystore.path: "${ES_CONFIG}/${ES_HTTPCERT}"
elasticsearch.ssl.certificateAuthorities: ["${ES_CONFIG}/${ES_KEYSTORE}"]
```


4. Add kibana user to group `elasticsearch`
```
usermod -a -G elasticsearch kibana
```

## SIEM stuff
Follow this guide: https://www.elastic.co/guide/en/siem/guide/current/install-siem.html

### Filebeat
1. Install Filebeat (https://www.elastic.co/guide/en/beats/filebeat/7.8/filebeat-modules-quickstart.html)
2. Update `/etc/filebeat/filebeat.yml`
```
  # ES info
  output.elasticsearch.hosts: "${ES_HOST}"
  output.elasticsearch.protocol: "http"
  output.elasticsearch.username: "${ES_USER}"
  output.elasticsearch.password: "${ES_PASSWD}"

  # ssl/tls info
  ssl.certificate_authorities: ["${ES_CONFIG}/${ES_KEYSTORE}"]
```
4. setup the paths you want to crawl
5. enable the logs you want

### Auditbeat
1. Install Auditbeat (https://www.elastic.co/guide/en/siem/guide/current/install-siem.html)
2. Update `/etc/auditbeat/auditbeat.yml`
```
  # ES info
  output.elasticsearch.hosts: "${ES_HOST}"
  output.elasticsearch.protocol: "http"
  output.elasticsearch.username: "${ES_USER}"
  output.elasticsearch.password: "${ES_PASSWD}"

  # ssl/tls info
  ssl.certificate_authorities: ["${ES_CONFIG}/${ES_KEYSTORE}"]
```

### Packetbeat
1. Install packetbeat (https://www.elastic.co/guide/en/beats/packetbeat/7.8/packetbeat-getting-started.html)
2. Update `/etc/auditbeat/auditbeat.yml`
```
  # ES info
  output.elasticsearch.hosts: "${ES_HOST}"
  output.elasticsearch.protocol: "http"
  output.elasticsearch.username: "${ES_USER}"
  output.elasticsearch.password: "${ES_PASSWD}"

  # ssl/tls info
  ssl.certificate_authorities: ["${ES_CONFIG}/${ES_KEYSTORE}"]
```

## SSL/TLS cert and key fixing (optional)
Change file permissions

```
chown elasticsearch.elasticsearch ${ES_CONFIG}/${ES_HTTPCERT}
chown elasticsearch.elasticsearch ${ES_CONFIG}/${ES_KEYSTORE}
```


## Logstash
1. Setup security: https://www.elastic.co/guide/en/beats/filebeat/current/configuring-ssl-logstash.html
2. Add user to group `elasticsearch`
```
usermod -a -G elasticsearch logstash
```
3. if you're using pfELK, you'll need to update `conf.d/*-outputs.conf` with the following
```
# 50-outputs.conf
output {
  if [type] == "firewall" {
    elasticsearch {
      id => "pfelk"
      hosts => ["http://{$ES_HOST}:9200"]
      # make sure this account has the correct permissions https://discuss.elastic.co/t/issues-sending-monitoring-data-from-logstash-to-elasticsearch/215103/8
      user => "logstash_system"
      password => "mypasswod"
      index => "pfelk-%{+YYYY.MM.dd}"
      ssl => true
      cacert => "${ES_CONFIG}/${ES_KEYSTORE}"
      manage_template => true
      template => "/etc/logstash/conf.d/templates/pf-geoip.json"
      template_name => "pf-geoip"
      template_overwrite => false
    }
  }
}
...
```

Note: Some of the requests sent to logstash can get quite large.  It may be worth adjusting `http.compression: true` and `http.max_content_length: 500mb` (https://www.elastic.co/guide/en/elasticsearch/reference/current/modules-http.html)

Now you may start all the beats and logstash
```
#!/bin/bash
service elasticsearch start &
wait %1
systemctl status --no-pager elasticsearch

service kibana start &
wait %1
systemctl status --no-pager kibana

service filebeat start &
wait %1
systemctl status --no-pager filebeat

service auditbeat start &
wait %1
systemctl status --no-pager auditbeat

service packetbeat start &
wait %1
systemctl status --no-pager packetbeat

service logstash start &
wait %1
systemctl status --no-pager logstash
```

----

# Elasticsearch Agent Installation


## Agent
1. Enable code execution, use powershell: https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-executionpolicy?view=powershell-7
```
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope LocalMachine
```
2. Download the agent `https://www.elastic.co/downloads/elastic-agent`
3. Add integration `http://${ES_HOST}:5601/app/ingestManager#/integrations`
4. Make sure to update the code to use `http`
5. Run with powershell as administrator

```
./elastic-agent enroll --insecure https://${ES_HOST} <your key>
./install-service-elastic-agent.ps1
```

6. Reenable back to RemoteSigned
```
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine
```
