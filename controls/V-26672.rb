control "V-26672" do
  title "The application must have the ability to retain a session lock
remaining in effect until the user re-authenticates using established
identification and authentication procedures."
  impact 0.5
  tag "nist": ["AC-11 b", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-33819r1_rule"
  tag "stig_id": "SRG-APP-000005"
  tag "cci": "CCI-000056"
  tag "check": "Design the domains of administration roles within Elasticsearch
by the principle of Separation of Duties.

As the application administrator (shown here as 'elasticsearch'), verify the
permissions for ES_HOME:

$ ls -la ${ES_HOME?}

If anything in ES_HOME is not owned by the application administrator, this is a
finding.

Next, as the elasticsearch administrator, run the following CURL command:


$ curl -XGET  -H 'Content-Type: application/json' -u <TEST_USER> -p
<TEST_CREDENTIALS> https://<elasticsearch>:9200/_xpack/security/role

Review the role permissions, if any role is listed as superuser but should not
have that access, this is a finding."
  tag "fix": "Enforce logical access restrictions with changes to application
configuration.

See the official documentation for the complete  guide on authorization
configuration:
https://www.elastic.co/guide/en/x-pack/current/authorization.html"
end
