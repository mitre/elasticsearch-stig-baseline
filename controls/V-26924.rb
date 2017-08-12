control "V-26924" do
  title "Encrypt information in transit both at the Elasticsearch perimeter and within\nthe Elasticsearch cluster\n"
  desc  "
    Use SSL / TLS communication for all networked access to Elasticsearch and
    connected components such as Kibana and Logstash.  X-Pack Security should be
    configured with organization approved cryptography.
    
  "
  impact 0.5
  tag "severity": "medium"
  tag "rid": "SV-34204r1_rule"
  tag "stig_id": "SRG-APP-000172"
  tag "cci": "CCI-000197"
  tag "nist": ["IA-5 (1) (c)", "Rev_4"]
  tag "check": "Application must utilize approved cryptography to protect passwords in\ntransmission.\rAs the application administrator (usually elasticsearch), check\nthe xpack.ssl settings are set to the correct values.\r\r$cat elasticsearch.yml\n| grep xpack.ssl\r\rxpack.ssl.key:                     <server_key>.key \nxpack.ssl.certificate:             <server_certificate>.crt \nxpack.ssl.certificate_authorities: [ <approved_ca>.crt\" ]     \r\rIf these\nsetting are not set or the underlining certificate and keys are not correct,\nthis is a finding.  \r\r$cat elasticsearch.yml | grep\nxpack.security.http.ssl.enabled: true\r\rIf this setting is not present or set\nto true, this is a finding. \r \r$cat elasticsearch.yml | grep\nxpack.security.transport.ssl.enabled: true\r\rIf this setting is not present or\nset to true, this is a finding.\r\rAs a elasticsearch user, check that\nnon-secure http traffic does not response with 200 status:\r\r$curl\nhttp://<elasticsearchIP:9200>/  \r\rIf a 200 response comes back, this is a\nfinding.\n"
  tag "fix": "Implement protective measures when enforcing password encryption for\ntransmission.       \r      \r See the official documentation for the complete \nguide on establishing SSL configuration:\nhttps://www.elastic.co/guide/en/x-pack/current/ssl-tls.html\n"
end
