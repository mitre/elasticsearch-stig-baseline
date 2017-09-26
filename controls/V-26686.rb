control "V-26686" do
  title "The application must monitor for unauthorized remote connections to
the information system on an organization-defined frequency."
  desc  "Configure X-Pack Alerting to periodically watch for unauthorized
access attempts to the system in X-Pack Security audit logs and notify out to
centralized incident systems and personnel."
  impact 0.5
  tag "nist": ["AC-17 (5)", "Rev_3"]
  tag "severity": "medium"
  tag "rid": "SV-33909r1_rule"
  tag "stig_id": "SRG-APP-000018"
  tag "cci": "CCI-000071"
  tag "check": "Moving audit information off of the systems creating the audit
events into a central location allows for the monitoring of unauthorized remote
connections on a organization-defined frequency. Verify 'rsyslog' is
configured to send all messages to a log aggregation server.

Check the configuration of 'rsyslog' with the following command:

# grep @ /etc/rsyslog.conf
   *.* @@logagg.site.mil

If there are no lines in the '/etc/rsyslog.conf' file that contain the '@'
or '@@' symbol(s), and the lines with the correct symbol(s) to send output to
another system do not cover all 'rsyslog' output, this is a finding.

As System owner, verify that elasticsearch audit logs are being monitored by
rsyslog.  Run the following command

$cat /etc/rsyslog.conf' | grep 'InputFileName
/var/log/elasticsearch/<clustername>_access.log'"
  tag "fix": "Modify the '/etc/rsyslog.conf' file to contain a configuration
line to send all 'rsyslog' output to a log aggregation system:

*.* @@&ltlog aggregation system name&gt

As System owner, configure rsyslog to monitor elasticsearch audit logs.  Run
the following command

$vi /etc/rsyslog.conf' | grep 'InputFileName
/var/log/elasticsearch/<clustername>_access.log'"
end
