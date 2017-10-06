control "V-30590" do
  title "The application must employ automated mechanisms to alert security
personnel of inappropriate or unusual activities with security implications."
  desc  "Utilize perimeter, application, centralized authentication, and
repository audit controls to audit the use of systems in real time with
sufficient context."
  impact 0.5
  tag "nist": ["SI-4 (12)", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-40335r1_rule"
  tag "gtitle": "SRG-APP-000237"
  tag "cci": "CCI-001274"
  tag "check": "Verify auditd rules are in place to monitor elasticsearch.yml;
this file contains security functions settings for elasticsearch.

As system owner, normally root, run the following command;

$auditctl -l | grep elasticsearch.yml

A watch rule covering all file access ~ -p war for the elasticsearch.yml file
be present, if this is not, this is a finding."
  tag "fix": "Implment audit rules for elasticsearch configuration settings.
All security functions, including the disabling and changing are maintained
within this file.

As the system owner, usually root, add the following to audit.rules, this file
is maintained at /etc/audit/rules.d/audit.rules on RHEL 7:

-w <ES_HOME>/config/elasticsearch.yml -p war -k elasticsearch-config"
end
