control "V-27016" do
  title "Applications must terminate user sessions upon user logout or any
other organization or policy defined session termination events such as idle
time limit exceeded."
  impact 0.5
  tag "nist": ["SC-23 (1)", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-34310r1_rule"
  tag "stig_id": "SRG-APP-000220"
  tag "cci": "CCI-001185"
  tag "check": "Elasticsearch meets this requirement through design and
implementation.

Elasticsearch provides communication through REST API calls and terminates all
session and network communication at the response of every call.  This is a
permanent not a finding. "
  tag "fix": "This requirement is a permanent not a finding. No fix is
required."
end
