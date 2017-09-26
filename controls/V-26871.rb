control "V-26871" do
  title "To support DoD requirements to centrally manage the content of audit
records, applications must provide the ability to write specified audit record
content to a centralized audit log repository.  "
  desc  "Offload and centralize audit records retention to a separate system
from the sources of audit records."
  impact 0.5
  tag "nist": ["AU-3 (2)", "Rev_3"]
  tag "severity": "medium"
  tag "rid": "SV-34151r1_rule"
  tag "stig_id": "SRG-APP-000102"
  tag "cci": "CCI-000136"
  tag "check": "Verify 'rsyslog' is configured to send specified messages to
a log aggregation server.

Check the configuration of 'rsyslog' with the following command:

# grep @ /etc/rsyslog.conf
   *.* @@logagg.site.mil

If there are no lines in the '/etc/rsyslog.conf' file that contain the '@'
or '@@' symbol(s), and the lines with the correct symbol(s) to send output to
another system do not cover specified 'rsyslog' output, this is a finding."
  tag "fix": "Modify the '/etc/rsyslog.conf' file to contain a configuration
line to send specified 'rsyslog' output to a log aggregation system:

*.* @@&ltlog aggregation system name&gt

"
end
