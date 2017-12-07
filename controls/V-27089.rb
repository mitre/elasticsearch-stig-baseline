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
  'es_home',
  description: 'Path elasticsearch home folder',
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

ELASTICSEARCH_CONF = attribute(
  'elasticsearch_conf',
  description: 'Path to elasticsearch.yml',
  default: '/etc/elasticsearch/elasticsearch.yml'
)

ES_INCLUDED_LOGEVENTS = attribute(
  'es_included_logevents',
  description: 'List of events to be logged',
  default: ['access_denied', 'anonymous_access_denied', 'authentication_failed',
     'connection_denied', 'tampered_request', 'run_as_denied', 'run_as_granted']
)

ES_EXCLUDED_LOGEVENTS = attribute(
  'es_excluded_logevents',
  description: 'List of events to be logged',
  default: ['access_granted']
)

only_if do
  service('elasticsearch').installed?
end

control "V-27089" do
  title "Applications must provide a report generation capability for audit
reduction data."
  desc  "Automate the creation of reports, dashboards, and interactive
exploration of audit records."
  impact 0.5
  tag "nist": ["AU-7", "Rev_3"]
  tag "severity": "medium"
  tag "rid": "SV-34384r1_rule"
  tag "gtitle": "SRG-APP-000114"
  tag "cci": "CCI-000157"
  tag "check": "Note: The following instructions use the ES_HOME environment
variable. See supplementary content APPENDIX-F for instructions on configuring
ES_HOME.

$ cat config/elasticsearch.yml | grep xpack.security.audit

Check elasticsearch settings and documentation to determine whether designated
personnel are able to select which auditable events are being audited.


As the application administrator (shown here as 'elasticsearch'), verify the
permissions for ES_HOME:

$ ls -la ${ES_HOME?}

If anything in ES_HOME is not owned by the application administrator, this is a
finding.

Next, as the elasticsearch administrator, run the following CURL command:


$ curl -XGET  -H 'Content-Type: application/json' -u <TEST_USER> -p
<TEST_CREDENTIALS> https://<elasticsearch>:9200/_xpack/security/role

Review the role permissions, if any role is listed as superuser but should not
have that access, this is a finding."
  tag "fix": "Configure elasticsearch audit settings based on selectable, event
criteria.

See the official documentation for the instructions on audit configuration:
https://www.elastic.co/guide/en/x-pack/current/auditing.html

As the system administrator, change the permissions of ES_HOME.

$ sudo chown -R elasticsearch:elasticsearch ${ES_HOME?}
$ sudo chmod 700 ${ES_HOME?}

"

  begin
    describe yaml(ELASTICSEARCH_CONF) do
      its(['xpack.security.audit.enabled']) { should eq true }
      its(['xpack.security.audit.outputs']) { should include 'logfile' }
      its(['xpack.security.audit.logfile.events.include']) { should match_array ES_INCLUDED_LOGEVENTS }
      its(['xpack.security.audit.logfile.events.exclude']) { should match_array ES_EXCLUDED_LOGEVENTS }
    end

    describe file(ELASTICSEARCH_CONF) do
      its('owner') { should eq ES_OWNER }
      its('group') { should eq ES_GROUP }
    end

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
    
  rescue Exception => msg
    describe "Exception: #{msg}" do
      it { should be_nil}
    end
  end
end
