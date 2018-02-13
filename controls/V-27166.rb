ES_SERVICE_NAME= attribute(
  'es_service_name',
  description: 'Name of Elasticsearch service',
  default: 'elasticsearch'
)

only_if do
  service(ES_SERVICE_NAME).installed?
end

control "V-27166" do
  title "The application must have the capability to produce audit records on
hardware-enforced, write-once media."
  desc  "Applicable - does not meet - not configurable, and does not meet the
requirement."
  impact 0.5
  tag "nist": ["AU-9 (1)", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-34465r1_rule"
  tag "gtitle": "SRG-APP-000124"
  tag "cci": "CCI-000165"
  tag "check": "Elasticsearch cannot support this requirement without
assistance from an external application, policy, or service."
  tag "fix": "Do not expose Elasticsearch directly to users, instead have an
application make requests on behalf of users."

  only_if do
    false
  end
end