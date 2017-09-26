control "V-26678" do
  title "The application must maintain the binding of security attributes to
information with sufficient assurance that the information/attribute
association can be used as the basis for automated policy actions."
  desc  "The JSON data models used by a system must maintain denormalized or
linked security labels and markings for information such that the information
can be used for automated policy actions by applications and Elasticsearch
security infrastructure. Utilize X-Pack Security's Field and Document Level
Security features to restrict access based on information within the document."
  impact 0.5
  tag "nist": ["AC-16 (3)", "Rev_3"]
  tag "severity": "medium"
  tag "rid": "SV-33877r1_rule"
  tag "stig_id": "SRG-APP-000011"
  tag "cci": "CCI-001426"
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
