control "V-26791" do
  title "Applications must enforce organizational-defined limitations on the
embedding of data types within other data types."
  desc  "The JSON data models used by a system must maintain denormalized or
linked security labels and markings for information such that the information
can be used for automated policy actions by applications and Elasticsearch
security infrastructure. Data in transit is protected via TLS. Utilize X-Pack
Security's Field and Document Level Security features to restrict access based
on information within the document."
  impact 0.5
  tag "nist": ["AC-4 (5)", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-34041r1_rule"
  tag "gtitle": "SRG-APP-000057"
  tag "cci": "CCI-000029"
  tag "check": "The JSON data models used by a system must maintain
denormalized or linked security labels and markings for information such that
the security labels can be changed by administrative personnel. Data in transit
is protected via TLS. Utilize X-Pack Security's Field and Document Level
Security features to restrict access based on information within the document.


As the security administrator, run the following CURL command:

$ curl -XGET  -H 'Content-Type: application/json' -u <TEST_USER> -p
<TEST_CREDENTIALS> https://<elasticsearch>:9200/_xpack/security/role

Review the role permissions, if any role is incorrect or does not provide
access to underliing data model, this is a finding."
  tag "fix": "As an administrative users, verify that you have access to
security labels within the data model.

See the official documentation for the complete  guide on authorization
configuration:
https://www.elastic.co/guide/en/x-pack/current/authorization.html"
end
