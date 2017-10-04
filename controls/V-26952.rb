control "V-26952" do
  title "Applications must automatically implement organizational-defined
safeguards and countermeasures if security functions (or mechanisms) are
changed inappropriately."
  desc  "Monitor the elasticsearch configuration on the system running
Elasticsearch software and notify operators when activity occurs. "
  impact 0.5
  tag "nist": ["CM-5 (7)", "Rev_3"]
  tag "severity": "medium"
  tag "rid": "SV-34235r1_rule"
  tag "gtitle": "SRG-APP-000134"
  tag "cci": "CCI-001500"
  tag "check": "Verify auditd rules are in place to monitor elasticsearch.yml;
this file contains security functions settings for elasticsearch.

As system owner, normally root, run the following command;

$auditctl -l | grep elasticsearch.yml

A watch rule covering all file access ~ -p war for the elasticsearch.yml file
be present, if this is not, this is a finding.
"
  tag "fix": "Implment audit rules for elasticsearch configuration settings.
All security functions, including the disabling and changing are maintained
within this file.

As the system owner, usually root, add the following to audit.rules, this file
is maintained at /etc/audit/rules.d/audit.rules on RHEL 7:

-w <ES_HOME>/config/elasticsearch.yml -p war -k elasticsearch-config"
end
