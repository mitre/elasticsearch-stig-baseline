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

ES_SERVICE_NAME= attribute(
  'es_service_name',
  description: 'Name of Elasticsearch service',
  default: 'elasticsearch'
)

only_if do
  service(ES_SERVICE_NAME).installed?
end

control "V-27059" do
  title "The application must maintain the integrity of information during
aggregation, packaging, and transformation in preparation for transmission."
  desc  "Use SSL / TLS communication for all networked access to Elasticsearch"
  impact 0.5
  tag "nist": ["SC-8 (2)", "Rev_3"]
  tag "severity": "medium"
  tag "rid": "SV-34354r1_rule"
  tag "gtitle": "SRG-APP-NA"
  tag "cci": "CCI-001129"
  tag "check": "Application must utilize approved cryptography to establish
integrity during preparation of data transmission.

As the application administrator (usually elasticsearch), check the xpack.ssl
settings are set to the correct values.

$cat elasticsearch.yml | grep xpack.ssl

xpack.ssl.key:                     <server_key>.key
xpack.ssl.certificate:             <server_certificate>.crt
xpack.ssl.certificate_authorities: [ <approved_ca>.crt' ]

If these setting are not set or the underlying certificate and keys are not
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
  tag "fix": "Implement integrity measures during preparation of data
transmission.

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
