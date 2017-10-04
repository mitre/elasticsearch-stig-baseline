only_if do
  service('elasticsearch').installed?
end

control "V-27017" do
  title "Applications providing a login capability must also provide a logout
functionality to allow the user to manually terminate the session."
  desc  "This requirement is a permanent not a finding. No fix is required."
  impact 0.0
  tag "nist": ["SC-23 (2)", "Rev_3"]
  tag "severity": "medium"
  tag "rid": "SV-34311r1_rule"
  tag "gtitle": "SRG-APP-000221"
  tag "cci": "CCI-001186"
  tag "check": "Elasticsearch meets this requirement through design and
implementation.

Elasticsearch provides logout capability through REST API calls and terminates
all session and network communication at the response of every call.  This is a
permanent not a finding. "
  tag "fix": "This requirement is a permanent not a finding. No fix is
required."

  only_if do
    false
  end
end

