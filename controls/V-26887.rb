control "V-26887" do
  title "Applications must configure their auditing to reduce the likelihood of
storage capacity being exceeded."
  desc  "Offload and centralize audit records retention to a separate system
from the sources of audit records."
  impact 0.5
  tag "nist": ["AU-4", "Rev_3"]
  tag "severity": "medium"
  tag "rid": "SV-34167r1_rule"
  tag "stig_id": "SRG-APP-000071"
  tag "cci": "CCI-000138"
  tag "check": "Check Elasticsearch.yml settings and existing audit records to
verify information specific to the nessacary content of the event is being
captured and stored with audit records.

As the application administrator (usually elasticsearch, check the
xpack.security.audit.outputs setting contains logfile by running the following:


$ cat config/elasticsearch.yml | grep xpack.security.audit

This setting allows for the customization of audits to reduce likelihood of
exceeding storage capavity.

For a complete list of extra information that can be added to log_line_prefix,
see the official documentation:
https://www.elastic.co/guide/en/x-pack/current/auditing.html      "
  tag "fix": "Configure elasticsearch audit settings to contain sufficient
information to establish where an event occured.

See the official documentation for the instructions on audit configuration:
https://www.elastic.co/guide/en/x-pack/current/auditing.html

If javaascript or python plugins are installed on the machine; run uninstall
command as follows:"
end
