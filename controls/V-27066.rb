control "V-27066" do
  title "The application must restrict error messages so only authorized
personnel may view them."
  desc  "Limit the access of users and administrators to error logs and
verbatim error log messages whether it be in application provided user
interfaces or the actual Elasticsearch error log. Ensure production has an
appropriate logging information level and is not set to a level left over from
development. Secure error logs with OS level protections."
  impact 0.5
  tag "nist": ["SI-11 b", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-34361r1_rule"
  tag "stig_id": "SRG-APP-000267"
  tag "cci": "CCI-001314"
  tag "check": "The error logs and audit logs should be restricited to
application owner. i.e. /var/log/elasticsearch/audit folder must have mode 0644
or less permissive for elasticsearch user.

As the application owner, check the permissions of audit logs; i.e.
/var/log/elasticsearch/audit, run the command:

 $ ls -l /var/log/elasticsearch/audit

If properly configured, the output should indicate the following permissions:
-rw------- and the owner should be the application owner. If it does not, this
is a finding.

As the application owner, check the permissions of error logs; i.e.
/var/log/elasticsearch/error, run the command:

 $ ls -l /var/log/elasticsearch/error

If properly configured, the output should indicate the following permissions:
-rw------- and the owner should be the application owner. If it does not, this
is a finding."
  tag "fix": "To properly set the owner of audit logs, i.e.
/var/log/elasticsearch/audit, run the command:

 $ sudo chown elasticsearch  /var/log/elasticsearch/audit

To properly set the permissions of audit logs, i.e.
/var/log/elasticsearch/audit, run the command:

$ sudo chmod 0600 /var/log/elasticsearch/audit

To properly set the owner of error logs, i.e. /var/log/elasticsearch/error, run
the command:

$ sudo chown elasticsearch  /var/log/elasticsearch/error

To properly set the permissions of error logs, i.e.
/var/log/elasticsearch/error, run the command:

$ sudo chmod 0600 /var/log/elasticsearch/error  "
end
