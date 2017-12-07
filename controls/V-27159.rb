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

only_if do
  service('elasticsearch').installed?
end

control "V-27159" do
  title "The application must protect the integrity and availability of
publicly available information and applications."
  desc  "Prevent tampering for publicly available information sets by setting
read-only access for application or anonymous access, as appropriate."
  impact 0.5
  tag "nist": ["SC-14", "Rev_3"]
  tag "severity": "medium"
  tag "rid": "SV-34458r1_rule"
  tag "gtitle": "SRG-APP-000201"
  tag "cci": "CCI-001149"
  tag "check": "Elasticsearch enforces access restrictions based on Role Based
Access Control. Other access controls should be handled by the Operating
System.

As the application administrator (shown here as 'elasticsearch'), verify the
permissions for ES_HOME:

$ ls -la ${ES_HOME?}

If anything in ES_HOME is not owned by the application administrator, this is a
finding.

As the elasticsearch administrator, run the following CURL command:

$ curl -XGET  -H 'Content-Type: application/json' -u <TEST_USER> -p
<TEST_CREDENTIALS> https://<elasticsearch>:9200/_xpack/security/role

Review the role permissions, if any role is incorrect or provides access to
cluster configuration outside of administrative roles, this is a finding."
  tag "fix": "Enforce the protection needs of public information in the same
manner as normal access restrictions.

See the official documentation for the complete  guide on authorization
configuration:
https://www.elastic.co/guide/en/x-pack/current/authorization.html"

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

  rescue Exception => msg
    describe "Exception: #{msg}" do
      it { should be_nil}
    end
  end
end
