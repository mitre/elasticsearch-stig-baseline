control "V-26903" do
  title "Generate Audits to assist monitoring and alerting of activities on the system
	"
  desc  "
    Utilize perimeter, application, centralized authentication, and repository
    audit controls to audit the use of systems in real time with sufficient
    context.  X-Pack Security audit controls should be enabled to audit the
    defaults of all HTTP/S based access to Elasticsearch.  All applications should
    use HTTP/S  rather than Elasticsearch transport protocol.

  "
  impact 0.5
  tag "severity": "medium"
  tag "rid": "SV-34183r1_rule"
  tag "stig_id": "SRG-APP-000091"
  tag "cci": "CCI-000172"
  tag "nist": ["AU-12 c", "Rev_4"]
  tag "check": "Check Elasticsearch.yml settings and existing audit records to verify
	information specific to the nessacary content of the event is being captured
	and stored with audit records.

	As the application administrator
	(usually elasticsearch, check the xpack.security.audit.outputs setting
	contains logfile by running the following:

	$ cat
	config/elasticsearch.yml | grep xpack.security.audit.outputs

	If this
	configuration setting is not present, this is a finding.  If this
	configuration setting does not contain logfile, this is a finding.

	For a
	complete list of extra information that can be added to log_line_prefix, see
	the official documentation:
	https://www.elastic.co/guide/en/x-pack/current/auditing.html

	 If
	the current settings do not provide enough information regarding the content
	of the event, this is a finding.
	"
  tag "fix": "Configure elasticsearch audit settings to contain sifficient information to
	establish where an event occured.

	See the official documentation for the
	instructions on audit configuration:
	https://www.elastic.co/guide/en/x-pack/current/auditing.html
	"
end
