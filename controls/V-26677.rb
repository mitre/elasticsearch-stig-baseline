control "V-26677" do
  title "The application must provide the capability to specify administrative
users and grant them the right to change application security attributes
pertaining to application data."
  desc  "The application controlled data model for security labels and markings
should be human readable and present in all stored and transferred data models."
  impact 0.5
  tag "nist": ["AC-16 (2)", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-33849r1_rule"
  tag "stig_id": "SRG-APP-000010"
  tag "cci": "CCI-001425"
  tag "check": "The JSON data models used by a system must maintain
denormalized or linked security labels and markings for information such that
the security labels can be changed by administravtive personnel. Data in
transit is protected via TLS. Utilize X-Pack Security's Field and Document
Level Security features to restrict access based on information within the
document.

As the security administrator, run the following CURL command:

$ curl -XGET  -H 'Content-Type: application/json' -u <TEST_USER> -p
<TEST_CREDENTIALS> https://<elasticsearch>:9200/_xpack/security/role

Review the role permissions, if any role is incorrect or does not provide
access to security labels of the underliing data model, this is a finding."
  tag "fix": "As an administrative users, verify that you have access to
security labels within the data model.

See the official documentation for the complete  guide on authorization
configuration:
https://www.elastic.co/guide/en/x-pack/current/authorization.html"
end
