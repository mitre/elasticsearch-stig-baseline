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

control "V-26891" do
  title "Applications must validate the binding of the information
producer\u0089Û¡ÌÝå»s identity to the information."
  desc  "Offload and centralize audit records retention to a separate system
from the sources of audit records."
  impact 0.5
  tag "nist": ["AU-10 (2)", "Rev_3"]
  tag "severity": "medium"
  tag "rid": "SV-34171r1_rule"
  tag "gtitle": "SRG-APP-000082"
  tag "cci": "CCI-001339"
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
