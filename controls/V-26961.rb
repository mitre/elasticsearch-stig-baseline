control "V-26961" do
  title "Applications must adhere to the principles of least functionality by
providing only essential capabilities."
  desc  "Separate administrative rights into three groups. User Administrators,
Cluster Administrators, and Index Administrators using X-Pack's RBAC and
limiting access to System accounts and configuration files with operating
system controls. Administrators of each type should not be given global
administrative controls outside of their job function."
  impact 0.5
  tag "nist": ["CM-7 a", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-34246r1_rule"
  tag "gtitle": "SRG-APP-000141"
  tag "cci": "CCI-000381"
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
