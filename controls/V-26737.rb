ES_SERVICE_NAME= attribute(
  'es_service_name',
  description: 'Name of Elasticsearch service',
  default: 'elasticsearch'
)

only_if do
  service(ES_SERVICE_NAME).installed?
end

control "V-26737" do
  title "The application must enforce dual authorization, based on
organizational policies and procedures for organizational-defined privileged
commands."
  desc  "Applicable - does not meet - not configurable, and does not meet the
requirement."
  impact 0.5
  tag "nist": ["AC-3 (2)", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-33985r1_rule"
  tag "gtitle": "SRG-APP-000034"
  tag "cci": "CCI-000021"
  tag "check": "Elasticsearch cannot support this requirement without
assistance from an external application, policy, or service."
  tag "fix": "Implement a Custom Realm within X-Pack security.

See the official documentation for the instructions on custom realms:
https://www.elastic.co/guide/en/x-pack/current/custom-realms.html#implementing-custom-realm"

  only_if do
    false
  end
end
