control "V-26893" do
  title "Applications must maintain reviewer/releaser identity and credentials
within the established chain of custody for all information reviewed or
released."
  desc  "The data models used by a system must maintain reviewer/releaser
identity and credentials within the object such that the information can be
used for automated policy actions by applications and Elasticsearch for review
or release."
  impact 0.5
  tag "nist": ["AU-10 (3)", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-34173r1_rule"
  tag "stig_id": "SRG-APP-000083"
  tag "cci": "CCI-001340"
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
