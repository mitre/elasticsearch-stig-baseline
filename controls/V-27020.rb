control "V-27020" do
  title "Applications must generate unique session identifiers with
organization-defined randomness requirements."
  desc  "Utilize shield cluster keys as well as supported clients to prevent
hijacking of connections or unexpected contention of updates. Elasticsearch
does not have a concept of sessions, but with shield communication ids are
unique, random, and signed to prevent tampering."
  impact 0.5
  tag "nist": ["SC-23 (3)", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-34314r1_rule"
  tag "stig_id": "SRG-APP-000224"
  tag "cci": "CCI-001188"
  tag "check": "Elasticsearch meets this requirement through design and
implementation.

Elasticsearch provides a unique session through REST API calls and terminates
all session and network communication at the response of every call through a
network.  This is a permanent not a finding. "
  tag "fix": "This requirement is a permanent not a finding. No fix is
required."
end
