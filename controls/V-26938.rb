control "V-26938" do
  title "The application must support the organizational requirement to employ
automated mechanisms enforcing access restrictions."
  desc  "Configure automated alarms to proactively notify when the security or
stability of the system is threatened"
  impact 0.5
  tag "nist": ["CM-5 (1)", "Rev_3"]
  tag "severity": "medium"
  tag "rid": "SV-34218r1_rule"
  tag "stig_id": "SRG-APP-000129"
  tag "cci": "CCI-000346"
  tag "check": "Elasticsearch enforces access restrictions based on Role Based
Acces Control. Other access controls should be handled by the Operating System.


As the application administrator (shown here as 'elasticsearch'), verify the
permissions for ES_HOME:

$ ls -la ${ES_HOME?}

If anything in ES_HOME is not owned by the application administrator, this is a
finding.

As the elasticsearch administrator, run the following CURL command:

$ curl -XGET  -H 'Content-Type: application/json' -u <TEST_USER> -p
<TEST_CREDENTIALS> https://<elasticsearch>:9200/_xpack/security/role

Review the role permissions, if any role is incorrect or provices access to
cluster configuration outside of administration roles, this is a finding."
  tag "fix": "Enforce logical access restrictions with changes to application
configuration.

See the official documentation for the complete  guide on authorization
configuration:
https://www.elastic.co/guide/en/x-pack/current/authorization.html"
end
