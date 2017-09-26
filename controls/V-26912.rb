control "V-26912" do
  title "Applications managing network connectivity must have the capability to
authenticate devices before establishing network connections by using
bidirectional authentication that is cryptographically based."
  desc  "Configure the centralized authentication service to enforce
organization policies such as valid certification path, trusted anchor."
  impact 0.5
  tag "nist": ["IA-3 (2)", "Rev_3"]
  tag "severity": "medium"
  tag "rid": "SV-34192r1_rule"
  tag "cci": "CCI-000781"
  tag "check": "Application must utilize approved cryptography to authenticate
devices.

$cat elasticsearch.yml | grep xpack.ssl

xpack.ssl.key:                     <server_key>.key
xpack.ssl.certificate:             <server_certificate>.crt
xpack.ssl.certificate_authorities: [ <approved_ca>.crt' ]

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
  tag "fix": "Implement approved cryptography to authenticate devices.

 See the official documentation for the complete  guide on establishing SSL
configuration: https://www.elastic.co/guide/en/x-pack/current/ssl-tls.html"
end
