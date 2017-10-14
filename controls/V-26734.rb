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

control "V-26734" do
  title "The application must employ automated mechanisms enabling authorized
users to make information sharing decisions based on access authorizations of
sharing partners and access restrictions on information to be shared."
  desc  "Plan for the capability to implement Discretionary Access Control
(DAC) with includes or excludes access to the single user. Utilize X-Pack
Security's Field and Document Level Security features to restrict access based
on information within the document."
  impact 0.5
  tag "nist": ["AC-21 (1)", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-33982r1_rule"
  tag "gtitle": "SRG-APP-000032"
  tag "cci": "CCI-000099"
  tag "check": "The JSON data models used by a system must maintain
denormalized or linked security labels and markings for information such that
the information can be used for automated policy actions by applications and
Elasticsearch security infrastructure. Data in transit is protected via TLS.
Utilize X-Pack Security's Field and Document Level Security features to
restrict access based on information within the document.

As the elasticsearch administrator, run the following CURL command:

$ curl -XGET  -H 'Content-Type: application/json' -u <TEST_USER> -p
<TEST_CREDENTIALS> https://<elasticsearch>:9200/_xpack/security/role

Review the role permissions, if any role is incorrect or provides access to
cluster configuration outside of administrative roles, this is a finding."
  tag "fix": "As a data owner, build a data model that is denormalized or
linked security labels and markings for information such that the information
can be used for automated policy actions by applications and Elasticsearch
security infrastructure.

See the official documentation for the complete  guide on authorization
configuration:
https://www.elastic.co/guide/en/x-pack/current/authorization.html"

  begin
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
