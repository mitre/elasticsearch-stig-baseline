ES_SERVICE_NAME= attribute(
  'es_service_name',
  description: 'Name of Elasticsearch service',
  default: 'elasticsearch'
)

only_if do
  service(ES_SERVICE_NAME).installed?
end

control "V-26929" do
  title "The application must protect audit data records and integrity by using
cryptographic mechanisms."
  desc  "Applicable - does not meet - not configurable, and does not meet the
requirement."
  impact 0.5
  tag "nist": ["AU-9 (3)", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-34209r1_rule"
  tag "gtitle": "SRG-APP-000126"
  tag "cci": "CCI-001350"
  tag "check": "Elasticsearch cannot support this requirement without
assistance from an external application, policy, or service."
  tag "fix": "Perform computation and application of a cryptographic-signed
hash using asymmetric cryptography on audit records. "

  only_if do
    false
  end
end
