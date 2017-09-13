control "V-26705" do
  title "Generate Audits to assist monitoring and alerting of activities on the
system"
  desc  "Utilize perimeter, application, centralized authentication, and
repository audit controls to audit the use of systems in real time with
sufficient context.  X-Pack Security audit controls should be enabled to audit
the defaults of all HTTP/S based access to Elasticsearch.  All applications
should use HTTP/S  rather than Elasticsearch transport protocol."
  impact 0.5
  tag "nist": ["AC-2 (4)", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-33948r1_rule"
  tag "stig_id": "SRG-APP-000026"
  tag "cci": "CCI-000018"
  tag "check": "Note: The following instructions use the ESHOME environment
variable. See supplementary content APPENDIX-F for instructions on configuring
ESHOME.

$ cat config/elasticsearch.yml | grep xpack.security.audit.outputs


Check elasticsearch settings and documentation to determine whether designated
personnel are able to select which auditable events are being audited.


As the application administrator (shown here as \"elasticsearch\"), verify the
permissions for ESHOME:

$ ls -la ${ESHOME?}

If anything in ESHOME is not owned by the application administrator, this is a
finding.

Next, as the elasticsearch administrator, run the following CURL command:


$ curl -XGET  -H 'Content-Type: application/json' -u <TEST_USER> -p
<TEST_CREDENTIALS> https://localhost:9200/_xpack/security/role

Review the role permissions, if any role is listed as superuser but should not
have that access, this is a finding."
  tag "fix": "Configure elasticsearch audit settings to audit account creation.


See the official documentation for the instructions on audit configuration:
https://www.elastic.co/guide/en/x-pack/current/auditing.html"
end
