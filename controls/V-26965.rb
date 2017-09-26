control "V-26965" do
  title "Applications must implement transaction recovery for systems that are
transaction-based."
  desc  "Elasticsearch utilizes a transaction log to ensure the writes are
recorded during crash and can be replayed during a recovery phase."
  impact 0.5
  tag "nist": ["CP-10 (2)", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-34250r1_rule"
  tag "stig_id": "SRG-APP-000144"
  tag "cci": "CCI-000553"
  tag "check": "Elasticsearch utilizes a transaction log to ensure the writes
are recorded during crash and can be replayed during a recovery phase.

This is a permanent not a finding."
  tag "fix": "This requirement is a permanent not a finding. No fix is
required."
end