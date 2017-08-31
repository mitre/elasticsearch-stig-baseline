control "V-26953" do
  title "Configure organization approved encryption"
  desc  "Configure X-Pack Security to use an organization approved FIPS 140-2
java cryptography provider."
  impact 0.5
  tag "nist": ["MA-4 (6)", "Rev_3"]
  tag "severity": "medium"
  tag "rid": "SV-34236r1_rule"
  tag "stig_id": "SRG-APP-000184"
  tag "cci": "CCI-000888"
  tag "check": "Application must utilize approved cryptography to protect the
integrity and confidentiality.
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
  tag "fix": "Implement protective measures when protecting integrity and
confidentiality.

 See the official documentation for the complete  guide on establishing SSL
configuration: https://www.elastic.co/guide/en/x-pack/current/ssl-tls.html"
end
