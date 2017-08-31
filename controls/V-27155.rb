control "V-27155" do
  title "Configure organization approved encryption"
  desc  "Configure X-Pack Security to use an organization approved FIPS 140-2
java cryptography provider."
  impact 0.5
  tag "nist": ["", "Rev_"]
  tag "severity": "medium"
  tag "rid": "SV-34454r1_rule"
  tag "stig_id": "SRG-APP-NA"
  tag "cci": "CCI-001148"
  tag "check": "Application must utilize approved cryptography to establish
implement digital signatures.

As the application administrator (usually elasticsearch), check the xpack.ssl
settings are set to the correct values.

$cat elasticsearch.yml | grep xpack.ssl

xpack.ssl.key:                     <server_key>.key
xpack.ssl.certificate:             <server_certificate>.crt
xpack.ssl.certificate_authorities: [ <approved_ca>.crt\" ]

If these setting are not set or the underlining certificate and keys are not
correct, this is a finding.

$cat elasticsearch.yml | grep xpack.ssl.cipher_suites:

If this setting is not present, or not set to FIPS-validated or NSA-approved
cryptography, this is a finding.

As a elasticsearch user, check that non-secure http traffic does not response
with 200 status:

$curl -H 'Content-Type: application/json' -u <TEST_USER> -p <TEST_CREDENTIALS>
http://<elasticsearchIP:9200>/

If a 200 response comes back, this is a finding."
  tag "fix": "Employ approved cryptography to implment digital signatures.


See the official documentation for the complete  guide on establishing SSL
configuration: https://www.elastic.co/guide/en/x-pack/current/ssl-tls.html"
end
