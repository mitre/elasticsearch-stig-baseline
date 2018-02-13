ES_SERVICE_NAME= attribute(
  'es_service_name',
  description: 'Name of Elasticsearch service',
  default: 'elasticsearch'
)

only_if do
  service(ES_SERVICE_NAME).installed?
end

control "V-26932" do
  title "The application must obscure feedback of authentication information
during the authentication process to protect the information from possible
exploitation/use by unauthorized individuals."
  desc  "Applicable - does not meet - not configurable, and does not meet the
requirement."
  impact 0.5
  tag "nist": ["IA-6", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-34212r1_rule"
  tag "gtitle": "SRG-APP-000178"
  tag "cci": "CCI-000206"
  tag "check": "Elasticsearch cannot support this requirement without
assistance from an external application, policy, or service."
  tag "fix": "Do not expose Elasticsearch directly to users, instead have an
application make requests on behalf of users. If this is not possible, have an
application to sanitize requests and responses from and to users."

  only_if do
    false
  end
end
