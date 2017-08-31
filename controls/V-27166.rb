only_if do
  service('elasticsearch').installed?
end

control "V-27166" do
  impact 0.5
  tag "nist": ["AU-9 (1)", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-34465r1_rule"
  tag "stig_id": "SRG-APP-000124"
  tag "cci": "CCI-000165"
  tag "check": "Elasticsearch cannot support this requirement without
assistance from an external application, policy, or service. This requirement
is NA."
  tag "fix": "This requirement is NA. No fix is required."

  only_if do
    false
  end

end
