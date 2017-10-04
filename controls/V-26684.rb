control "V-26684" do
  title "The application must employ automated mechanisms to facilitate the
monitoring and control of remote access methods."
  desc  "Collect Elasticsearch X-Pack Security audit records from all
Elasticsearch nodes in near-real time to enable audit monitoring."
  impact 0.5
  tag "nist": ["AC-17 (1)", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-33904r1_rule"
  tag "gtitle": "SRG-APP-000016"
  tag "cci": "CCI-000067"
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
  tag "fix": "Configure elasticsearch audit settings to audit access methods.

See the official documentation for the instructions on audit configuration:
https://www.elastic.co/guide/en/x-pack/current/auditing.html"
end
