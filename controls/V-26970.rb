control "V-26970" do
  title "The application must alert designated organizational officials in the
event of an audit processing failure."
  desc  "Utilize perimeter, application, centralized authentication, and
repository audit controls to audit the use of systems in real time with
sufficient context.  X-Pack Security audit controls should be enabled to audit
the defaults of all HTTP/S based access to Elasticsearch.  All applications
should use HTTP/S  rather than Elasticsearch transport protocol."
  impact 0.5
  tag "nist": ["AU-5 a", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-34257r1_rule"
  tag "gtitle": "SRG-APP-000108"
  tag "cci": "CCI-000139"
  tag "check": "Verify the operating system immediately notifies the SA and
ISSO (at a minimum) when allocated audit record storage volume reaches
<DETERMINED_THRESHOLD> percent of the repository maximum audit record storage
capacity.

Check the system configuration to determine the partition the audit records are
being written to with the following command:

# grep log_file /etc/audit/auditd.conf log_file =
/var/log/elasticsearch/audit/audit.log

Check the size of the partition that audit records are written to (with the
example being \\\"/var/log/elasticsearch/audit/\\\"):

# df -h /var/log/elasticsearch/audit/ 0.9G /var/log/elasticsearch/audit

If the audit records are not being written to a partition specifically created
for audit records (in this example \\\"/var/log/elasticsearch/audit\\\" is a
separate partition), determine the amount of space other files in the partition
are currently occupying with the following command:

# du -sh <partition> 1.8G /var  Determine what the threshold is for the system
to take action when <DETERMINED_THRESHOLD> percent of the repository maximum
audit record storage capacity is reached:

# grep -i space_left /etc/audit/auditd.conf space_left = 225

If the value of the \\\"space_left\\\" keyword is not set to
ABS(1-<DETERMINED_THRESHOLD>) percent of the total partition size, this is a
finding."
  tag "fix": "Configure the operating system to immediately notify the SA and
ISSO (at a minimum) when allocated audit record storage volume reaches
<DETERMINED_THRESHOLD> percent of the repository maximum audit record storage
capacity.

Check the system configuration to determine the partition the audit records are
being written to:

# grep log_file /etc/audit/auditd.conf

Determine the size of the partition that audit records are written to (with the
example being \\\"/var/log/elasticsearch/audit/\\\"):

# df -h /var/log/elasticsearch/audit/

Set the value of the \\\"space_left\\\" keyword in
\\\"/etc/audit/auditd.conf\\\" to <DETERMINED_THRESHOLD> percent of the
partition size."
end
