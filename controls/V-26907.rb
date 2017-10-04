
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

MANAGED_ACCESS_POINTS= attribute(
  'managed_access_points',
  description: 'List of managed access points',
  default: ['10.0.2.15']
)

ES_ADMIN = attribute(
  'es_admin',
  description: 'Elasticsearch admin',
  default: 'elastic'
)
ES_PASS = attribute(
  'es_pass',
  description: 'Elasticsearch admin password',
  default: 'changeme'
)

only_if do
  service('elasticsearch').installed?
end

control "V-26907" do
  title "The application must use organizational-defined replay-resistant
authentication mechanisms for network access to privileged accounts."
  desc  "Configure PKI authentication, TLS/SSL, and cluster key features of
X-pack Security so that authentication and communication within Elasticsearch
is replay resistant."
  impact 0.5
  tag "nist": ["IA-2 (8)", "Rev_3"]
  tag "severity": "medium"
  tag "rid": "SV-34187r1_rule"
  tag "gtitle": "SRG-APP-000156"
  tag "cci": "CCI-000774"
  tag "check": "Application must utilize approved cryptography to authenticate
non-local maintenance sessions.

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
  tag "fix": "Implement approved cryptography to authenticate non-local
maintenance sessions.

 See the official documentation for the complete  guide on establishing SSL
configuration: https://www.elastic.co/guide/en/x-pack/current/ssl-tls.html"

  begin
    describe yaml(ELASTICSEARCH_CONF) do
      its(['xpack.security.http.filter.enabled']) { should eq true }
      its(['xpack.security.http.filter.allow']) { should be_in MANAGED_ACCESS_POINTS }
      its(['xpack.security.http.filter.deny']) { should eq '_all' }
    end

    cmd = "curl -H 'Content-Type: application/json' https://#{ELASTIC_IP}:#{ELASTIC_PORT}/_cluster/settings -k -u #{ES_ADMIN}:#{ES_PASS}"
    describe json(command:cmd) do
      its('persistent') { should be_empty }
      its('transient') { should be_empty }
    end

  rescue Exception => msg
    describe "Exception: #{msg}" do
      it { should be_nil}
    end
  end
end
