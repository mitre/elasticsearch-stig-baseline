control "V-26945" do
  title "The organization must employ automated mechanisms to restrict the use
of maintenance tools to authorized personnel only."
  desc  "Isolate maintenance functions from non-maintenance functions(Cluster
health) with the use of RBAC under the principle of least privilege.
Maintenance users should not be granted roles and privileges beyond what is
necessary to diagnose the system."
  impact 0.5
  tag "nist": ["MA-3 (4)", "Rev_3"]
  tag "severity": "medium"
  tag "rid": "SV-34227r1_rule"
  tag "stig_id": "SRG-APP-NA"
  tag "cci": "CCI-000872"
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
