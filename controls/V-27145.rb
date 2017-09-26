control "V-27145" do
  title "Applications must provide the capability to automatically process
audit records for events of interest based upon selectable, event criteria."
  desc  "Deploy security analytics to monitor the behavior of system users and
administrators. Audit events should be exportable, searchable, filterable, and
summarized in real time."
  impact 0.5
  tag "nist": ["AU-7 (1)", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-34444r1_rule"
  tag "stig_id": "SRG-APP-000115"
  tag "cci": "CCI-000158"
  tag "check": "Note: The following instructions use the ES_HOME environment
variable. See supplementary content APPENDIX-F for instructions on configuring
ES_HOME.

$ cat config/elasticsearch.yml | grep xpack.security.audit

Check elasticsearch settings and documentation to determine whether designated
personnel are able to select which auditable events are being audited.


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
  tag "fix": "Configure elasticsearch audit settings based on selectable, event
criteria.

See the official documentation for the instructions on audit configuration:
https://www.elastic.co/guide/en/x-pack/current/auditing.html"
end
