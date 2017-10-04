control "V-27073" do
  title "Applications must provide the capability to centralize the review and
analysis of audit records from multiple components within the system."
  desc  "Offload and centralize audit records retention to a separate system
from the sources of audit records."
  impact 0.5
  tag "nist": ["AU-6 (4)", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-34368r1_rule"
  tag "gtitle": "SRG-APP-000111"
  tag "cci": "CCI-000154"
  tag "check": "Verify 'rsyslog' is configured to send all messages to a log
aggregation server.

Check the configuration of 'rsyslog' with the following command:

# grep @ /etc/rsyslog.conf
   *.* @@logagg.site.mil

If there are no lines in the '/etc/rsyslog.conf' file that contain the '@'
or '@@' symbol(s), and the lines with the correct symbol(s) to send output to
another system do not cover all 'rsyslog' output, this is a finding."
  tag "fix": "Modify the '/etc/rsyslog.conf' file to contain a configuration
line to send all 'rsyslog' output to a log aggregation system:

*.* @@&ltlog aggregation system name&gt

"
end
