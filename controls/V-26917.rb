control "V-26917" do
  title "The application must enforce configurable traffic volume thresholds
representing auditing capacity for network traffic."
  desc  "Monitor the health and resources (such as remaining storage) of
systems running Elasticsearch software and notify operators when safety
thresholds have been exceeded. "
  impact 0.5
  tag "nist": ["AU-5 (3)", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-34197r1_rule"
  tag "stig_id": "SRG-APP-000105"
  tag "cci": "CCI-000145"
  tag "check": "Elasticsearch cannot support this requirement without
assistance from an external application, policy, or service."
  tag "fix": "Integrate network traffic control solutions outside of
elasticsearch."
end
