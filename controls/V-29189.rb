control "V-29189" do
  title "Applications must isolate security functions enforcing access and
information flow control from both non-security functions and from other
security functions."
  desc  "Isolate security functions from non security functions with the use of
RBAC under the principle of least privilege. administrative users should not be
granted roles and privileges beyond what is necessary to administer the system."
  impact 0.5
  tag "nist": ["SC-3 (2)", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-37460r1_rule"
  tag "gtitle": "SRG-APP-000235"
  tag "cci": "CCI-001086"
  tag "check": "Design the domains of administrative roles within Elasticsearch
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
