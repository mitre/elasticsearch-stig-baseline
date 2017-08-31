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
  description: 'Path to elasticsearch.yaml',
  default: '/etc/elasticsearch/elasticsearch.yml'
)

only_if do
  service('elasticsearch').installed?
end

control "V-27140" do
  title "Configure organization approved encryption"
  desc  "Configure X-Pack Security to use an organization approved FIPS 140-2
java cryptography provider."
  impact 0.5
  tag "nist": ["SC-13", "Rev_3"]
  tag "severity": "medium"
  tag "rid": "SV-34439r1_rule"
  tag "stig_id": "SRG-APP-000196"
  tag "cci": "CCI-001144"
  tag "check": "Application must utilize approved cryptography that complying
with applicable federal laws, Executive Orders, directives, policies,
regulations, standards, and guidance.

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
  tag "fix": "Employ approved cryptography that complying with applicable
federal laws, Executive Orders, directives, policies, regulations, standards,
and guidance.

See the official documentation for the complete  guide on establishing SSL
configuration: https://www.elastic.co/guide/en/x-pack/current/ssl-tls.html"

  begin
    describe yaml(ELASTICSEARCH_CONF) do
      its(['xpack.ssl.key']) { should_not be_nil }
      its(['xpack.ssl.certificate']) { should_not be_nil }
      its(['xpack.ssl.certificate_authorities']) { should_not be_nil }
      its(['xpack.security.http.ssl.enabled']) { should eq true }
      its(['xpack.security.transport.ssl.enabled']) { should eq true }
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
