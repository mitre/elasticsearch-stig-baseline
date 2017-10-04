control "V-27041" do
  title "Applications must limit the use of resources by priority and not
impede the host from servicing processes designated as a higher-priority."
  desc  "Elasticsearch is a single process and can be prioritized at the OS
level"
  impact 0.5
  tag "nist": ["SC-6", "Rev_3"]
  tag "severity": "medium"
  tag "rid": "SV-34335r1_rule"
  tag "gtitle": "SRG-APP-000248"
  tag "cci": "CCI-001096"
  tag "check": "Check elasticsearch service priority level via Operating System
priority settings. Make sure it is below high-priority processes.

As the system administrator (usually root, check the NICE setting is set at 0
or <ORGANIZATIONAL_DETERMINED> level.:

$ ps -efo pid,nice,comm | grep elasticsearch

If this NICE level is lower than 0 or <ORGANIZATIONAL_DETERMINED> level, this
is a finding.
"
  tag "fix": "Configure elasticsearch service to a lower priority level via
Operating System priority settings.

Set the default nice value for the application administrator in the
/etc/security/limits.conf file.

$ sudo su - root
$ vi /etc/security/limits.conf

Set the hard priority for the application administrator:
     elasticsearch hard priority 1"
end
