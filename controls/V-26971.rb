only_if do
  service('elasticsearch').installed?
end

control "V-26971" do
  title "The application must support and must not impede organizational
requirements to conduct backups of information system documentation including
security-related documentation per organizational-defined frequency."
  desc  "This requirement is a permanent not a finding. No fix is required."
  impact 0.0
  tag "nist": ["CP-9 (c)  ", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-34258r1_rule"
  tag "gtitle": "SRG-APP-000147"
  tag "cci": "CCI-000539"
  tag "check": "Elasticsearch meets this requirement through design and
implementation.

Elasticsearch supports this requirement and cannot be configured to be out of
compliance. This is a permanent not a finding. "
  tag "fix": "This requirement is a permanent not a finding. No fix is
required."

  only_if do
    false
  end
end
