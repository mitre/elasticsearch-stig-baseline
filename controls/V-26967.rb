control "V-26967" do
  title "The application must reject or delay, as defined by the
organizational, network traffic generated above configurable traffic volume
thresholds."
  desc  "Allocate Hard drive space for audit logs for minimum number of days
for normal load. Monitor the health and resources (such as remaining storage)
of systems running Elasticsearch software and notify operators when safety
thresholds have been exceeded. Automated system notification via email or http
endpoint can be built as an action in Watcher."
  impact 0.5
  tag "nist": ["AU-5 (3)", "Rev_3"]
  tag "severity": "medium"
  tag "rid": "SV-34252r1_rule"
  tag "gtitle": "SRG-APP-000106"
  tag "cci": "CCI-001574"
  tag "check": "Verify the audit records are stored on a separate disk than
operating system.

Check the system configuration to determine the partition the audit records are
being written to with the following command:

# grep log_file /etc/audit/auditd.conf log_file =
/var/log/elasticsearch/audit/audit.log

Check the size of the partition that audit records are written to (with the
example being '/var/log/elasticsearch/audit/'):

# df -h /var/log/elasticsearch/audit/ 0.9G /var/log/elasticsearch/audit

If the audit records are not being written to a partition specifically created
for audit records (in this example '/var/log/elasticsearch/audit' is a
separate partition), this is a finding."
  tag "fix": "Configure the audit storage to a separate partition for audit
storage.

Check the system configuration to determine the partition the audit records are
being written to:

# grep log_file /etc/audit/auditd.conf

Determine the size of the partition that audit records are written to (with the
example being '/var/log/elasticsearch/audit/'):

# df -h /var/log/elasticsearch/audit/    "
end
