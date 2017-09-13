control "V-27168" do
  title "Move Audit records off Elasticsearch boxes"
  desc  "Offload and centralize audit records retention to a separate system
from the sources of audit records."
  impact 0.5
  tag "nist": ["AU-9 (2)", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-34467r1_rule"
  tag "stig_id": "SRG-APP-000125"
  tag "cci": "CCI-001348"
  tag "check": "Check Elasticsearch.yml settings and existing audit records are
being recorded to an external system or media.

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
  tag "fix": "Configure elasticsearch audit settings to an external system or
media.

See the official documentation for the instructions on audit configuration:
https://www.elastic.co/guide/en/x-pack/current/auditing.html"
end
