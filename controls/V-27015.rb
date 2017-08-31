control "V-27015" do
  title "Enable secured communication to and within the Elasticsearch cluster"
  desc  "Configure PKI authentication, TLS/SSL, IP filtering; which are key
features of X-Pack Security. This should ensure that authentication and
communication within Elasticsearch is SSL Mutual Authentication."
  impact 0.5
  tag "nist": ["SC-23", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-34309r1_rule"
  tag "stig_id": "SRG-APP-000219"
  tag "cci": "CCI-001184"
  tag "check": "Application must utilize approved cryptography to ensure
authentication of both client and server during the entire session..

As the application administrator (usually elasticsearch), check the xpack.ssl
settings are set to the correct values.

$cat elasticsearch.yml | grep xpack.ssl

xpack.ssl.key:                     <server_key>.key
xpack.ssl.certificate:             <server_certificate>.crt
xpack.ssl.certificate_authorities: [ <approved_ca>.crt\" ]

If these setting are not set or the underlining certificate and keys are not
correct, this is a finding.

$cat elasticsearch.yml | grep xpack.security.http.ssl.enabled: true

If this setting is not present or set to false, this is a finding.

As a elasticsearch user, check that non-secure http traffic does not response
with 200 status:

$curl -H 'Content-Type: application/json' -u <TEST_USER> -p <TEST_CREDENTIALS>
http://<elasticsearchIP:9200>/

If a 200 response comes back, this is a finding."
  tag "fix": "Ensure authentication of both client and server during the entire
session.

 See the official documentation for the complete  guide on establishing SSL
configuration: https://www.elastic.co/guide/en/x-pack/current/ssl-tls.html"
end
