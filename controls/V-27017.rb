control "V-27017" do
  title "Applications providing a login capability must also provide a logout
functionality to allow the user to manually terminate the session."
  desc  "Kibana is a UI presentation layer for elasticsearch. Within the UI the
Logout function ends the user's session"
  impact 0.5
  tag "nist": ["SC-23 (2)", "Rev_3"]
  tag "severity": "medium"
  tag "rid": "SV-34311r1_rule"
  tag "stig_id": "SRG-APP-000221"
  tag "cci": "CCI-001186"
  tag "check": "Elasticsearch meets this requirement through design and
implementation.

Elasticsearch provides logout capability through REST API calls and terminates
all session and network communication at the response of every call.  This is a
permanent not a finding. "
  tag "fix": "This requirement is a permanent not a finding. No fix is
required."
end
