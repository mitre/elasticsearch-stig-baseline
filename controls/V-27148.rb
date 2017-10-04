control "V-27148" do
  title "The application must protect audit information from any type of
unauthorized access."
  desc  "Utilize perimeter, application, centralized authentication, and
repository audit controls to audit the use of systems in real time with
sufficient context.  X-Pack Security audit controls should be enabled to audit
the defaults of all HTTP/S based access to Elasticsearch.  All applications
should use HTTP/S  rather than Elasticsearch transport protocol."
  impact 0.5
  tag "nist": ["AU-9", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-34447r1_rule"
  tag "gtitle": "SRG-APP-000118"
  tag "cci": "CCI-000162"
  tag "check": "The owner of all log files written by the application should be
elasticsearch. These log files are determined by the
xpack.security.audit.output parameter in elasticsearch.yml and typically all
appear in /var/log/elasticsearch/audit. To see the owner of a given log file,
run the following command:

$ ls -l LOGFILE

If the owner is not root, this is a finding."
  tag "fix": "The owner of all log files written by the application should be
elasticsearch. These log files are determined by the
xpack.security.audit.output parameter in elasticsearch.yml and typically all
appear in /var/log/elasticsearch/audit.

For each log file LOGFILE referenced in xpack.security.audit.output from
elasticsearch.yml, run the following command to inspect the file's owner:

$ ls -l LOGFILE

If the owner is not elasticsearch, run the following command to correct this:

$ sudo chown elasticsearch LOGFILE"
end
