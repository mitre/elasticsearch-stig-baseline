control "V-27085" do
  title "The application must provide an audit reduction capability."
  desc  "Automate the creation of reports, dashboards, and interactive
exploration of audit records."
  impact 0.5
  tag "nist": ["AU-7", "Rev_3"]
  tag "severity": "medium"
  tag "rid": "SV-34380r1_rule"
  tag "gtitle": "SRG-APP-000113"
  tag "cci": "CCI-000156"
  tag "check": "Check Elasticsearch.yml settings and existing audit records to
verify information specific to the necessary content of the event is being
captured and stored with audit records.

As the application administrator (usually elasticsearch, check the
xpack.security.audit.outputs setting contains logfile by running the following:


$ cat config/elasticsearch.yml | grep xpack.security.audit.outputs

If this configuration setting is not present, this is a finding.  If this
configuration setting does not contain logfile, this is a finding.

For a complete list of extra information that can be added to log_line_prefix,
see the official documentation:
https://www.elastic.co/guide/en/x-pack/current/auditing.html

 If the current settings do not provide enough information regarding the
content of the event, this is a finding."
  tag "fix": "Configure elasticsearch audit settings to contain sufficient
information to establish where an event occurred.

See the official documentation for the instructions on audit configuration:
https://www.elastic.co/guide/en/x-pack/current/auditing.html"
end
