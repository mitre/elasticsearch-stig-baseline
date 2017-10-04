control "V-26675" do
  title "The application must maintain and support the use of organizational
defined security attributes to information in transmission."
  desc  "The JSON data models used by a system must maintain denormalized or
linked security labels and markings for information such that the information
can be used for automated policy actions by applications and Elasticsearch
security infrastructure. Data in transit is protected via TLS. Utilize X-Pack
Security's Field and Document Level Security features to restrict access based
on information within the document."
  impact 0.5
  tag "nist": ["AC-16", "Rev_3"]
  tag "severity": "medium"
  tag "rid": "SV-33823r1_rule"
  tag "gtitle": "SRG-APP-000008"
  tag "cci": "CCI-001401"
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
