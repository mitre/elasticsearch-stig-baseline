RSYSLOG_CONF= attribute(
  'rsyslog_conf',
  description: 'Path to rsyslog.conf',
  default: '/etc/rsyslog.conf'
)

LOG_AGGREGATION_SYSTEM = attribute(
  'log_aggregation_system',
  description: 'URI to the log aggregation system',
  default: 'logagg.site.mil'
)

ES_SERVICE_NAME= attribute(
  'es_service_name',
  description: 'Name of Elasticsearch service',
  default: 'elasticsearch'
)

only_if do
  service(ES_SERVICE_NAME).installed?
end

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
  tag "gtitle": "SRG-APP-000102"
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
