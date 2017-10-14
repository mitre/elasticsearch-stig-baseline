ELASTIC_IP= attribute(
  'elastic_ip',
  description: 'IP address of the elasticsearch instance',
  default: '0.0.0.0'
)
ELASTIC_PORT= attribute(
  'elastic_port',
  description: 'Port address of the elasticsearch instance',
  default: '9200'
)
ELASTICSEARCH_CONF= attribute(
  'elasticsearch_conf',
  description: 'Path to elasticsearch.yml',
  default: '/etc/elasticsearch/elasticsearch.yml'
)

APPROVED_CIPHER_SUITES= attribute(
  'elasticsearch_conf',
  description: 'List of NSA-approved or FIPS validated cipher suites',
  default: [
            'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256',
            'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256',
            'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA',
            'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
            'TLS_RSA_WITH_AES_128_CBC_SHA256',
            'TLS_RSA_WITH_AES_128_CBC_SHA'
            ]
)

only_if do
  service('elasticsearch').installed?
end

control "V-27154" do
  title "Applications must employ FIPS-validated cryptography to protect
unclassified information when such information must be separated from
individuals who have the necessary clearances yet lack the necessary access
approvals."
  desc  "Configure X-Pack Security to use an organizational approved FIPS 140-2
java cryptography provider."
  impact 0.5
  tag "nist": ["SC-13 (3)", "Rev_3"]
  tag "severity": "medium"
  tag "rid": "SV-34453r1_rule"
  tag "gtitle": "SRG-APP-000199"
  tag "cci": "CCI-001147"
  tag "check": "Application must utilize approved cryptography for data
separation.

As the application administrator (usually elasticsearch), check the xpack.ssl
settings are set to the correct values.

$cat elasticsearch.yml | grep xpack.ssl

xpack.ssl.key:                     <server_key>.key
xpack.ssl.certificate:             <server_certificate>.crt
xpack.ssl.certificate_authorities: [ <approved_ca>.crt' ]

If these setting are not set or the underlying certificate and keys are not
correct, this is a finding.

$cat elasticsearch.yml | grep xpack.ssl.cipher_suites:

If this setting is not present, or not set to FIPS-validated or NSA-approved
cryptography, this is a finding.

As a elasticsearch user, check that non-secure http traffic does not response
with 200 status:

$curl -H 'Content-Type: application/json' -u <TEST_USER> -p <TEST_CREDENTIALS>
http://<elasticsearchIP:9200>/

If a 200 response comes back, this is a finding."
  tag "fix": "Employ approved cryptography for data separations.

See the official documentation for the complete  guide on establishing SSL
configuration: https://www.elastic.co/guide/en/x-pack/current/ssl-tls.html"

  begin
    describe yaml(ELASTICSEARCH_CONF) do
      its(['xpack.ssl.key']) { should_not be_nil }
      its(['xpack.ssl.certificate']) { should_not be_nil }
      its(['xpack.ssl.certificate_authorities']) { should_not be_nil }
      its(['xpack.ssl.cipher_suites']) { should match_array APPROVED_CIPHER_SUITES }
    end

    describe command("openssl rsa -in #{yaml(ELASTICSEARCH_CONF)['xpack.ssl.key']} -check -noout") do
      its('stdout'){ should match /RSA key ok/ }
    end

    describe x509_certificate(yaml(ELASTICSEARCH_CONF)['xpack.ssl.certificate']) do
      it { should be_certificate }
      it { should be_valid }
    end

    if yaml(ELASTICSEARCH_CONF)['xpack.ssl.certificate_authorities'].is_a?(Array)
      yaml(ELASTICSEARCH_CONF)['xpack.ssl.certificate_authorities'].each do |cert|
        describe x509_certificate(cert) do
          it { should be_certificate }
          it { should be_valid }
        end
      end
    else
      describe x509_certificate(yaml(ELASTICSEARCH_CONF)['xpack.ssl.certificate_authorities']) do
        it { should be_certificate }
        it { should be_valid }
      end
    end

    describe command("curl -H 'Content-Type: application/json' http://#{ELASTIC_IP}:#{ELASTIC_PORT}/") do
      its('exit_status') { should_not cmp 0 }
    end

  rescue Exception => msg
    describe "Exception: #{msg}" do
      it { should be_nil}
    end
  end
end