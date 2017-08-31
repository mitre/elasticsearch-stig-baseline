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
  description: 'Path to elasticsearch.yaml',
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

ES_SUPERUSERS = attribute(
  'es_superusers',
  description: 'List of superusers',
  default: ['elastic']
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
  description: 'Path to elasticsearch.yaml',
  default: '/etc/elasticsearch/elasticsearch.yml'
)

ES_INCLUDED_LOGEVENTS = attribute(
  'es_included_logevents',
  description: 'List of events to be logged',
  default: ['access_denied', 'anonymous_access_denied', 'authentication_failed',
     'connection_denied', 'tampered_request', 'run_as_denied', 'run_as_granted']
)

ES_EXCLUDED_LOGEVENTS = attribute(
  'es_included_logevents',
  description: 'List of events to be logged',
  default: ['access_granted']
)

only_if do
  service('elasticsearch').installed?
end

control "V-26902" do
  title "Generate Audits to assist monitoring and alerting of activities on the
system"
  desc  "Utilize perimeter, application, centralized authentication, and
repository audit controls to audit the use of systems in real time with
sufficient context.  X-Pack Security audit controls should be enabled to audit
the defaults of all HTTP/S based access to Elasticsearch.  All applications
should use HTTP/S  rather than Elasticsearch transport protocol."
  impact 0.5
  tag "nist": ["AU-12 b", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-34182r1_rule"
  tag "stig_id": "SRG-APP-000090"
  tag "cci": "CCI-000171"
  tag "check": "Note: The following instructions use the ESHOME environment
variable. See supplementary content APPENDIX-F for instructions on configuring
ESHOME.

$ cat config/elasticsearch.yml | grep xpack.security.audit.outputs


Check elasticsearch settings and documentation to determine whether designated
personnel are able to select which auditable events are being audited.


As the application administrator (shown here as \"elasticsearch\"), verify the
permissions for ESHOME:

$ ls -la ${ESHOME?}

If anything in ESHOME is not owned by the application administrator, this is a
finding.

Next, as the elasticsearch administrator, run the following CURL command:


$ curl -XGET  -H 'Content-Type: application/json' -u <TEST_USER> -p
<TEST_CREDENTIALS> https://localhost:9200/_xpack/security/role

Review the role permissions, if any role is listed as superuser but should not
have that access, this is a finding."

  begin
    describe yaml(ELASTICSEARCH_CONF) do
      its(['xpack.security.audit.enabled']) { should eq true }
      its(['xpack.security.audit.outputs']) { should include 'logfile' }
      its(['xpack.security.audit.logfile.events.include']) { should match_array ES_INCLUDED_LOGEVENTS }
      its(['xpack.security.audit.logfile.events.exclude']) { should match_array ES_EXCLUDED_LOGEVENTS }
    end

    describe file(ES_HOME) do
      its('owner') { should eq ES_OWNER }
      its('group') { should eq ES_GROUP }
    end

    cmd = "curl -XGET  -H 'Content-Type: application/json' https://#{ELASTIC_IP}:#{ELASTIC_PORT}/_xpack/security/user -k -u #{ES_ADMIN}:#{ES_PASS}"
    userlist = json(command:cmd).params

    userlist.keys.each do |user|
      if userlist[user]['roles'].include?('superuser')
        describe userlist[user]['username'] do
          it { should be_in ES_SUPERUSERS}
        end
      end
    end

  rescue Exception => msg
    describe "Exception: #{msg}" do
      it { should be_nil}
    end
  end
end
