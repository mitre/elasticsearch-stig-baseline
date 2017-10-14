only_if do
  service('elasticsearch').installed?
end

control "V-26676" do
  title "The application must dynamically reconfigure security attributes in
accordance with an identified security policy as information is created and
combined."
  desc  "Applicable - does not meet - not configurable, and does not meet the
requirement."
  impact 0.5
  tag "nist": ["AC-16 (1)", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-33847r1_rule"
  tag "gtitle": "SRG-APP-000009"
  tag "cci": "CCI-001424"
  tag "check": "Elasticsearch cannot support this requirement without 
  assistance from an external application, policy, or service."
  tag "fix": "As appropriate, grant Role Based Access Control for 
  organizational users, non-organizational users, and anonymous users."

  only_if do
    false
  end
end
