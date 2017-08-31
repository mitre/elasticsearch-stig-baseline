control "V-27092" do
  title "Information in transit is protected by standard TLS communication, and
can be visible to specific system monitoring tools"
  desc  "Use SSL / TLS communication for all networked access to Elasticsearch
and connected components such as Kibana and Logstash.  X-Pack Security should
be configured with organization approved cryptography."
  impact 0.5
  tag "nist": ["SI-4 (10)", "Rev_3"]
  tag "severity": "medium"
  tag "rid": "SV-34387r1_rule"
  tag "stig_id": "SRG-APP-000282"
  tag "cci": "CCI-001272"
  tag "check": "Application must utilize approved cryptography to protect
passwords in transmission.
As the application administrator (usually elasticsearch), check the xpack.ssl
settings are set to the correct values.

$cat elasticsearch.yml | grep xpack.ssl

xpack.ssl.key:                     <server_key>.key
xpack.ssl.certificate:             <server_certificate>.crt
xpack.ssl.certificate_authorities: [ <approved_ca>.crt\" ]

If these setting are not set or the underlining certificate and keys are not
correct, this is a finding.

$cat elasticsearch.yml | grep xpack.security.http.ssl.enabled:

If this setting is set to false, this is a finding.

$cat elasticsearch.yml | grep xpack.security.transport.ssl.enabled:

If this setting is set to false, this is a finding.

As a elasticsearch user, check that non-secure http traffic does not response
with 200 status:

$curl -H 'Content-Type: application/json' -u <TEST_USER> -p <TEST_CREDENTIALS>
http://<elasticsearchIP:9200>/

If a 200 response comes back, this is a finding."
  tag "fix": "Implement protective measures when enforcing password encryption
for transmission.

 See the official documentation for the complete  guide on establishing SSL
configuration: https://www.elastic.co/guide/en/x-pack/current/ssl-tls.html"
end