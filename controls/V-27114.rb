only_if do
  service('elasticsearch').installed?
end

control "V-27114" do
  title "The application must terminate all sessions and network connections
when non-local maintenance is completed."
  desc  "Cluster shutdown will end all session and network connection"
  impact 0.0
  tag "nist": ["MA-4 e", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-34411r1_rule"
  tag "gtitle": "SRG-APP-000186"
  tag "cci": "CCI-000879"
  tag "check": "Elasticsearch meets this requirement through design and
implementation.

Elasticsearch provides non-local maintenance through REST API calls and
terminates all session and network communication at the response of every call
through a network.  This is a permanent not a finding. "
  tag "fix": "This requirement is a permanent not a finding. No fix is
required."

  only_if do
    false
  end
end
