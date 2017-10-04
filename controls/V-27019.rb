only_if do
  service('elasticsearch').installed?
end

control "V-27019" do
  title "Applications must recognize only system-generated session identifiers."
  desc  "This requirement is a permanent not a finding. No fix is required."
  impact 0.0
  tag "nist": ["SC-23 (3)", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-34313r1_rule"
  tag "gtitle": "SRG-APP-000223"
  tag "cci": "CCI-001664"
  tag "check": "Elasticsearch meets this requirement through design and
implementation.

Elasticsearch provides a unique session through REST API calls and terminates
all session and network communication at the response of every call.  This is a
permanent not a finding. "
  tag "fix": "This requirement is a permanent not a finding. No fix is
required."

  only_if do
    false
  end
end