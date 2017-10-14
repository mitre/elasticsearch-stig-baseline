only_if do
  service('elasticsearch').installed?
end

control "V-26664" do
  title "The application must be able to define the maximum number of
concurrent sessions for an application account globally, by account type, by
account, or a combination thereof. "
  desc  "Applicable - does not meet - not configurable, and does not meet the
requirement."
  impact 0.5
  tag "nist": ["AC-10", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-33786r1_rule"
  tag "gtitle": "SRG-APP-000001"
  tag "cci": "CCI-000054"
  tag "check": "Elasticsearch cannot support this requirement without
assistance from an external application, policy, or service."
  tag "fix": "Do not expose Elasticsearch directly to users, instead have an
application make requests on behalf of users.

Limit the number of connections from clients (connection pool size) in the
client's initialization settings to limit the impact of Denial of Service
attacks. Connection pools are shared amongst API calls from different users as
there is no session concept within Elasticsearch."

  only_if do
    false
  end
end
