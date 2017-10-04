only_if do
  service('elasticsearch').installed?
end

control "V-26680" do
  title "The application must display security attributes in human-readable
form on each object output from the system to system output devices to identify
an organizational-identified set of special dissemination, handling, or
distribution instructions using organizational-identified human readable,
standard naming conventions."
  desc  "The application controlled data model for security labels and markings
should be human readable and present in all stored and transferred data models."
  impact 0.0
  tag "nist": ["AC-16 (5)", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-33879r1_rule"
  tag "gtitle": "SRG-APP-000013"
  tag "cci": "CCI-001428"
  tag "check": "Elasticsearch meets this requirement through design and
implementation.

Elasticsearch supports this requirement and cannot be configured to be out of
compliance. This is a permanent not a finding. "
  tag "fix": "This requirement is a permanent not a finding. No fix is
required."

  only_if do
    false
  end
end
