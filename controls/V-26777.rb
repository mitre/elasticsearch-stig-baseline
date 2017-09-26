
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

control "V-26777" do
  title "Applications must uniquely identify destination domains for
information transfer."
  desc  "Limit network access to Elasticsearch software from known points of
origin with the use of software and hardware firewalls as well as X-Pack
Security IP Filtering. Change the elasticsearch cluster name to an instance
unique value for all elasticsearch nodes and transport client nodes in the
system."
  impact 0.5
  tag "nist": ["AC-4 (17) (a)", "Rev_3"]
  tag "severity": "medium"
  tag "rid": "SV-34027r1_rule"
  tag "stig_id": "SRG-APP-000051"
  tag "cci": "CCI-001555"
  tag "check": "Check Elasticsearch.yml settings and existing IP filtering
rules to verify that only sepecific IP behind hardware/software 'Managed
access control points' are listed.

As the application administrator (usually elasticsearch, check the
xpack.security.http.filter setting contains IP address(es) of the  'Managed
access control points':

$cat elasticsearch.yml | grep 'xpack.security.http.filter', Verify all three
settings; xpack.security.http.filter.enabled: true;
xpack.security.http.filter.allow: 'Managed access control points';
xpack.security.http.filter.deny: _all

As an elasticsearch administrator test; verify runtime environment within
_culster settings are set to '{}' OR Verify all three settings are
xpack.security.http.filter.enabled: true; xpack.security.http.filter.allow:
'Managed access control points'; xpack.security.http.filter.deny: _all

$curl -H 'Content-Type: application/json' -u <TEST_USER> -p <TEST_CREDENTIALS>
-XGET 'http://<elasticsearch>:9200/_cluster/settings'

If these configuration setting are disabled, or not pointing to the 'Managed
access control points', this is a finding. "
  tag "fix": "Note: The following instructions use the ES_HOME environment
variable. See supplementary content APPENDIX-XXX for
instructions on configuring ES_HOME.

To change the Managed access control points of the application, as the
application administrator, change the following setting in elasticsearch.conf:


$ sudo su - elasticsearch
$ vi $ES_HOME/config/elasticsearch.yml

Change the Managed access control points parameter to the desired addresses,
i.e.:
     xpack.security.http.filter.enabled: true
     xpack.security.http.filter.allow: 'Managed access control points'
     xpack.security.http.filter.deny: _all

Next, restart the application:
$ sudo su - elasticsearch

# SYSTEMD SERVER ONLY
$ systemctl restart elasticsearch"

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
    describe do
      skip "Exception: #{msg}"
    end
  end
end
