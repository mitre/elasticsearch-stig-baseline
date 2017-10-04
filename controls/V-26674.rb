control "V-26674" do
  title "The application must support and maintain the binding of
organizational defined security attributes to information in process."
  desc  "The application controlled data model for security labels and markings
should be human readable and present in all stored and transferred data models."
  impact 0.5
  tag "nist": ["AC-16", "Rev_3"]
  tag "severity": "medium"
  tag "rid": "SV-33821r1_rule"
  tag "gtitle": "SRG-APP-000007"
  tag "cci": "CCI-001400"
  tag "check": "The JSON data models used by a system must maintain
denormalized or linked security labels and markings for information such that
the information can be used for automated policy actions by applications and
Elasticsearch security infrastructure. Data in transit is protected via TLS.
Utilize X-Pack Security's Field and Document Level Security features to
restrict access based on information within the document."
  tag "fix": "As a data owner, build a data model that is denormalized or
linked security labels and markings for information such that the information
can be used for automated policy actions by applications and Elasticsearch
security infrastructure."
end
