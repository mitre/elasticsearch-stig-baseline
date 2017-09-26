control "V-26665" do
  title "The application must ensure that the screen display is obfuscated when
an application session lock event occurs."
  impact 0.5
  tag "nist": ["AC-11 (1)", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-33794r1_rule"
  tag "stig_id": "SRG-APP-000002"
  tag "cci": "CCI-000060"
  tag "check": "Elasticsearch meets this requirement through design and
implementation.

Elasticsearch provides a unique session through REST API calls and terminates
all session and network communication at the response of every call.  Any
screen based obfustration would be provided by the operating system.  This is a
permanent not a finding. "
  tag "fix": "This requirement is a permanent not a finding. No fix is
required."
end
