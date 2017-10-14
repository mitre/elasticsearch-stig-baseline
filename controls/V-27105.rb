only_if do
  service('elasticsearch').installed?
end

control "V-27105" do
  title "The application must support taking organizational-defined list of
least-disruptive actions to terminate suspicious events."
  desc  "Applicable - does not meet - not configurable, and does not meet the
requirement."
  impact 0.5
  tag "nist": ["SI-4 (7)", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-34400r1_rule"
  tag "gtitle": "SRG-APP-000287"
  tag "cci": "CCI-001670"
  tag "check": "Elasticsearch cannot support this requirement without
assistance from an external application, policy, or service."
  tag "fix": "Do not expose Elasticsearch directly to users, instead have an
application make requests on behalf of users."

  only_if do
    false
  end
end
