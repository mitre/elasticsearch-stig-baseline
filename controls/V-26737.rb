control "V-26737" do
  title "The application must enforce dual authorization, based on
organizational policies and procedures for organization-defined privileged
commands."
  impact 0.5
  tag "nist": ["AC-3 (2)", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-33985r1_rule"
  tag "stig_id": "SRG-APP-000034"
  tag "cci": "CCI-000021"
  tag "check": "Elasticsearch cannot support this requirement without
assistance from an external application, policy, or service."
  tag "fix": "Implement a Custom Realm within X-Pack security.

See the official documentation for the instructions on custom realms:
https://www.elastic.co/guide/en/x-pack/current/custom-realms.html#implementing-custom-realm"
end
