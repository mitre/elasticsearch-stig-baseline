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

control "V-27062" do
  title "Encrypt information in transit both at the Elasticsearch perimeter and
within the Elasticsearch cluster"
  desc  "Use SSL / TLS communication for all networked access to Elasticsearch
and connected components such as Kibana and Logstash.  X-Pack Security should
be configured with organization approved cryptography."
  impact 0.5
  tag "severity": "medium"
  tag "rid": "SV-34357r1_rule"
  tag "stig_id": "SRG-APP-000230"
  tag "cci": "CCI-001132"
  tag "check": "Application must utilize approved cryptography to protect data
transmission.

As the application administrator (usually elasticsearch), check the xpack.ssl
settings are set to the correct values.

$cat elasticsearch.yml | grep xpack.ssl

xpack.ssl.key:                     <server_key>.key
xpack.ssl.certificate:             <server_certificate>.crt
xpack.ssl.certificate_authorities: [ <approved_ca>.crt\" ]

If these setting are not set or the underlining certificate and keys are not
correct, this is a finding.

$cat elasticsearch.yml | grep xpack.security.http.ssl.enabled: true

If this setting is not present or set to true, this is a finding.

$cat elasticsearch.yml | grep xpack.security.transport.ssl.enabled: true

If this setting is not present or set to true, this is a finding.

As a elasticsearch user, check that non-secure http traffic does not response
with 200 status:

$curl http://<elasticsearchIP:9200>/

If a 200 response comes back, this is a finding."
  tag "fix": "Implement protective measures during data transmission.

 See the official documentation for the complete  guide on establishing SSL
configuration: https://www.elastic.co/guide/en/x-pack/current/ssl-tls.html"

  describe yaml(ELASTICSEARCH_CONF) do
    its(['xpack.ssl.key']) { should_not be_nil }
    its(['xpack.ssl.certificate']) { should_not be_nil }
    its(['xpack.ssl.certificate_authorities']) { should_not be_nil }
    its(['xpack.security.http.ssl.enabled']) { should eq true }
    its(['xpack.security.transport.ssl.enabled']) { should eq true }
  end

  describe file(yaml(ELASTICSEARCH_CONF)['xpack.ssl.key']) do
    it { should be_file }
  end

  describe file(yaml(ELASTICSEARCH_CONF)['xpack.ssl.certificate']) do
    it { should be_file }
  end

  yaml(ELASTICSEARCH_CONF)['xpack.ssl.certificate_authorities'].each do |cert|
    describe file(cert) do
      it { should be_file }
    end
  end

  describe command("curl http://#{ELASTIC_IP}:#{ELASTIC_PORT}/") do
    its('exit_status') { should cmp 52 }
  end


end
