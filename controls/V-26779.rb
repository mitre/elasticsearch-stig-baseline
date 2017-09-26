control "V-26779" do
  title "The application must bind security attributes to information to
facilitate information flow policy enforcement."
  desc  "The application controlled data model for security labels and markings
should be human readable and present in all stored and transferred data models."
  impact 0.5
  tag "nist": ["AC-4 (17) (b)", "Rev_3"]
  tag "severity": "medium"
  tag "rid": "SV-34029r1_rule"
  tag "stig_id": "SRG-APP-000052"
  tag "cci": "CCI-000223"
  tag "check": "The JSON data models used by a system must maintain
denormalized or linked security labels and markings for information such that
the information can be used for attribution. Data in transit is protected via
TLS. Utilize X-Pack Security's Field and Document Level Security features to
restrict access based on information within the document.

As the elasticsearch administrator, run the following CURL command:

$ curl -XGET  -H 'Content-Type: application/json' -u <TEST_USER> -p
<TEST_CREDENTIALS> https://<elasticsearch>:9200/_xpack/security/role

Review the role permissions, if any role is incorrect or provices access to
cluster configuration outside of administration roles, this is a finding."
  tag "fix": "As a data owner, build a data model that is denormalized or
linked security labels and markings for information such that the information
can be used for attribution.

See the official documentation for the complete  guide on authorization
configuration:
https://www.elastic.co/guide/en/x-pack/current/authorization.html"
end
