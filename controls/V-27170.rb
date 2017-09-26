control "V-27170" do
  title "The application must associate security attributes with information
exchanged between information systems."
  desc  "The JSON data models used by a system must maintain denormalized or
linked security labels and markings for information such that the information
can be used for automated policy actions by applications and Elasticsearch
security infrastructure. Utilize X-Pack Security's Field and Document Level
Security features to restrict access based on information within the document."
  impact 0.5
  tag "nist": ["SC-16", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-34469r1_rule"
  tag "stig_id": "SRG-APP-000203"
  tag "cci": "CCI-001157"
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
