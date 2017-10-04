only_if do
  service('elasticsearch').installed?
end

control "V-26666" do
  title "The application must support the requirement to initiate a session
lock after an organizational defined time period of system or application
inactivity has transpired."
  desc  "The default session duration is set in the kibana.yml configuration
file. By default, sessions expire after 30 minutes. The timeout is specified in
milliseconds and is configurable."
  impact 0.0
  tag "nist": ["AC-11 a", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-33797r1_rule"
  tag "gtitle": "SRG-APP-000003"
  tag "cci": "CCI-000057"
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

