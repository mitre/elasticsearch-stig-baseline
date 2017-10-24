RSYSLOG_CONF= attribute(
  'rsyslog_conf',
  description: 'Path to rsyslog.conf',
  default: '/etc/rsyslog.conf'
)

LOG_AGGREGATION_SYSTEM = attribute(
  'rsyslog_conf',
  description: 'URI to the log aggregation system',
  default: 'logagg.site.mil'
)

only_if do
  service('elasticsearch').installed?
end

control "V-27152" do
  title "The application must protect audit information from unauthorized
modification."
  desc  "Offload and centralize audit records retention to a separate system
from the sources of audit records."
  impact 0.5
  tag "nist": ["AU-9", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-34451r1_rule"
  tag "gtitle": "SRG-APP-000119"
  tag "cci": "CCI-000163"
  tag "check": "Moving audit information off of the systems creating the audit
events protects the information from unauthorized modification. Verify
'rsyslog' is configured to send all messages to a log aggregation server.

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
  begin
    describe file(RSYSLOG_CONF) do
      its('content') { should match /@@+#{LOG_AGGREGATION_SYSTEM}|@+#{LOG_AGGREGATION_SYSTEM}/}
    end

  rescue Exception => msg
    describe "Exception: #{msg}" do
      it { should be_nil}
    end
  end
end
