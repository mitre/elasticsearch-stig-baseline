control "V-26890" do
  title "The application must associate the identity of the information
producer with the information."
  desc  "Offload and centralize audit records retention to a separate system
from the sources of audit records."
  impact 0.5
  tag "nist": ["AU-10 (1)", "Rev_3"]
  tag "severity": "medium"
  tag "rid": "SV-34170r1_rule"
  tag "gtitle": "SRG-APP-000081"
  tag "cci": "CCI-001338"
  tag "check": "Moving audit records to a centralized location will assist in
the investigation and non-repudiation of audited actions. Verify 'rsyslog' is
configured to send all messages to a log aggregation server.

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
