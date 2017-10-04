control "V-26730" do
  title "The application must automatically audit account disabling actions and
notify appropriate individuals."
  desc  "Utilize perimeter, application, centralized authentication, and
repository audit controls to audit the use of systems in real time with
sufficient context.  X-Pack Security audit controls should be enabled to audit
the defaults of all HTTP/S based access to Elasticsearch.  All applications
should use HTTP/S  rather than Elasticsearch transport protocol."
  impact 0.5
  tag "nist": ["AC-2 (4)", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-33978r1_rule"
  tag "gtitle": "SRG-APP-000028"
  tag "cci": "CCI-001404"
  tag "check": "Note: The following instructions use the ES_HOME environment
variable. See supplementary content APPENDIX-F for instructions on configuring
ES_HOME.

$ cat config/elasticsearch.yml | grep xpack.security.audit.outputs


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
  tag "fix": "Configure elasticsearch audit settings to contain sufficient
information to establish account disabling.

See the official documentation for the instructions on audit configuration:
https://www.elastic.co/guide/en/x-pack/current/auditing.html"
end
