only_if do
  service('elasticsearch').installed?
end

control "V-26671" do
  title "Applications must ensure that users can directly initiate session lock
mechanisms which prevent further access to the system."
  desc  "Elasticsearch meets this requirement through design and
implementation.

Elasticsearch provides a unique session through REST API calls and terminates
all session and network communication at the response of every call.  A lock is
not needed since the session is already terminated.  This is a permanent not a
finding. "
  impact 0.0
  tag "nist": ["AC-11 a", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-33818r1_rule"
  tag "gtitle": "SRG-APP-000004"
  tag "cci": "CCI-000058"
  tag "check": "Elasticsearch meets this requirement through design and
implementation.

Elasticsearch provides a unique session through REST API calls and terminates
all session and network communication at the response of every call.  A lock is
not needed since the session is already terminated.  This is a permanent not a
finding. "
  tag "fix": "This requirement is a permanent not a finding. No fix is
required."

  only_if do
    false
  end
end
