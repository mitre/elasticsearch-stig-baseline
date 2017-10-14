only_if do
  service('elasticsearch').installed?
end

control "V-30589" do
  title "The application must use cryptographic mechanisms to protect the
integrity of audit tools."
  desc  "Applicable - does not meet - not configurable, and does not meet the
requirement."
  impact 0.5
  tag "nist": ["AU-9 (3)", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-40333r1_rule"
  tag "gtitle": "SRG-APP-000290"
  tag "cci": "CCI-001496"
  tag "check": "Elasticsearch cannot support this requirement without
assistance from an external application, policy, or service."
  tag "fix": "Although the application cannot fulfill a crypytological
mechanism for protection, there are a number of protects that can be put in
place. Utilize Elasticsearch Signing Key (PGP key D88E42B4, available from
https://pgp.mit.edu) and create rules for auditd on elasticsearch.yml file."

  only_if do
    false
  end
end
