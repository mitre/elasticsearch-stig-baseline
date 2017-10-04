control "V-27159" do
  title "The application must protect the integrity and availability of
publicly available information and applications."
  desc  "Prevent tampering for publicly available information sets by setting
read-only access for application or anonymous access, as appropriate."
  impact 0.5
  tag "nist": ["SC-14", "Rev_3"]
  tag "severity": "medium"
  tag "rid": "SV-34458r1_rule"
  tag "gtitle": "SRG-APP-000201"
  tag "cci": "CCI-001149"
  tag "check": "Elasticsearch enforces access restrictions based on Role Based
Access Control. Other access controls should be handled by the Operating
System.

As the application administrator (shown here as 'elasticsearch'), verify the
permissions for ES_HOME:

$ ls -la ${ES_HOME?}

If anything in ES_HOME is not owned by the application administrator, this is a
finding.

As the elasticsearch administrator, run the following CURL command:

$ curl -XGET  -H 'Content-Type: application/json' -u <TEST_USER> -p
<TEST_CREDENTIALS> https://<elasticsearch>:9200/_xpack/security/role

Review the role permissions, if any role is incorrect or provides access to
cluster configuration outside of administrative roles, this is a finding."
  tag "fix": "Enforce the protection needs of public information in the same
manner as normal access restrictions.

See the official documentation for the complete  guide on authorization
configuration:
https://www.elastic.co/guide/en/x-pack/current/authorization.html"
end
