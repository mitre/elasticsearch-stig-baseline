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

ES_HOME= attribute(
  'elasticsearch_conf',
  description: 'Path to elasticsearch.yml',
  default: '/etc/elasticsearch'
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

ES_OWNER = attribute(
  'es_owner',
  description: 'Elasticsearch owner',
  default: 'elasticsearch'
  )

ES_GROUP = attribute(
  'es_group',
  description: 'Elasticsearch owner',
  default: 'elasticsearch'
  )

MANAGED_ACCESS_POINTS= attribute(
  'managed_access_points',
  description: 'List of managed access points',
  default: ['10.0.2.15']
)


only_if do
  service('elasticsearch').installed?
end

control "V-26735" do
  title "The application must enforce approved authorizations for logical
access to the system in accordance with applicable policy."
  desc  "Plan for granting temporary authorizations, with known automated
expiration times, to enable users to implement out of the ordinary processes."
  impact 0.5
  tag "nist": ["AC-3", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-33983r1_rule"
  tag "gtitle": "SRG-APP-000033"
  tag "cci": "CCI-000213"
  tag "check": "Verify that role-based policies are in place and access
enforcement mechanisms are in place.

As the elasticsearch administrator, run the following CURL command:

$ curl -XGET  -H 'Content-Type: application/json' -u <TEST_USER> -p
<TEST_CREDENTIALS> https://<elasticsearch>:9200/_xpack/security/role

Review the role permissions, if any role is incorrect or provides access to
cluster configuration outside of administrative roles, this is a finding.

Check Elasticsearch.yml settings and existing IP filtering rules to verify that
only specific IP behind hardware/software 'Managed access control points'
are listed.

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
  tag "fix": "Implement strong access controls to secure application data by
establishing role-based policies and access control mechanisms.

To establish role-based policies; see the official documentation on
authorization;
https://www.elastic.co/guide/en/x-pack/current/authorization.html.

Note: The following instructions use the ES_HOME environment variable. See
supplementary content APPENDIX-XXX for instructions on configuring ES_HOME.

To establish an access control mechanism; as the application administrator,
change the following setting in elasticsearch.yml:

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

    describe file(ES_HOME) do
      its('owner') { should eq ES_OWNER }
      its('group') { should eq ES_GROUP }
    end

    cmd = "curl -XGET  -H 'Content-Type: application/json' https://#{ELASTIC_IP}:#{ELASTIC_PORT}/_xpack/security/role -k -u #{ES_ADMIN}:#{ES_PASS}"
    role_list = json(command:cmd).params

    role_list.keys.each do |role|
      describe role_list[role] do
        its(['run_as']) { should_not include("*") }
      end
      describe role_list[role] do
        its(['indices']) { should_not include({"names"=>["*"], "privileges"=>["all"]}) }
      end
      describe role_list[role] do
        its(['cluster']) { should_not include("all") }
      end
    end

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
