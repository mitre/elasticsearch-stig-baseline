control "V-27034" do
  title "Applications must prevent unauthorized and unintended information
transfer via shared system resources."
  desc  "Separate access to production Elasticsearch systems from developers
both at the host operating system, storage subsystems, networks, and
Elasticsearch software through Role Based Access Control as required by policy.
Access to the internal network of the Elasticsearch cluster should not allow
access to production data."
  impact 0.5
  tag "nist": ["SC-4", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-34328r1_rule"
  tag "stig_id": "SRG-APP-000243"
  tag "cci": "CCI-001090"
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
