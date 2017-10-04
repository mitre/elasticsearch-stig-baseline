control "V-26929" do
  title "The application must protect audit data records and integrity by using
cryptographic mechanisms."
  desc  "Elasticsearch currently does not provide protection and integrity
checks on audit logs. A secondary process would be needed to periodically roll
and sign audit logs."
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
end
