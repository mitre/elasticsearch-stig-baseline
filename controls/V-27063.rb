control "V-27063" do
  title "Disable dynamic templates"
  desc  "Dynamic templates allows for user input to be processed without
verifying it against a set of expected values. Turning off dynamic templates,
and creating templates for input can handle type validation."
  impact 0.5
  tag "nist": ["SI-10", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-34358r1_rule"
  tag "stig_id": "SRG-APP-000251"
  tag "cci": "CCI-001310"
  tag "check": "Application must utilize approved cryptography to validate data
input.

As the application administrator (usually elasticsearch), check the xpack.ssl
settings are set to the correct values.

$cat elasticsearch.yml | grep xpack.ssl

xpack.ssl.key:                     <server_key>.key
xpack.ssl.certificate:             <server_certificate>.crt
xpack.ssl.certificate_authorities: [ <approved_ca>.crt\" ]

If these setting are not set or the underlining certificate and keys are not
correct, this is a finding.

$cat elasticsearch.yml | grep xpack.security.http.ssl.enabled

If this setting is set to false, this is a finding.

$cat elasticsearch.yml | grep xpack.security.transport.ssl.enabled

If this setting is set to false, this is a finding.

As a elasticsearch user, check that non-secure http traffic does not response
with 200 status:

$curl -H 'Content-Type: application/json' -u <TEST_USER> -p <TEST_CREDENTIALS>
http://<elasticsearchIP:9200>/

If a 200 response comes back, this is a finding."
  tag "fix": "Implement protective measures to validate data inputs.

 See the official documentation for the complete  guide on establishing SSL
configuration: https://www.elastic.co/guide/en/x-pack/current/ssl-tls.html"
end
