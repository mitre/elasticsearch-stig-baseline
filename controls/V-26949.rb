control "V-26949" do
  title "Applications must limit privileges to change the software resident
within software libraries (including privileged programs)."
  desc  "Install or Upgrade Elasticsearch software with an operating system
account restricted to appropriate users and configured to have only the
permissions necessary to complete the installation or upgrade."
  impact 0.5
  tag "nist": ["CM-5 (6)", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-34232r1_rule"
  tag "stig_id": "SRG-APP-000133"
  tag "cci": "CCI-001499"
  tag "check": "Design the domains of administration roles within Elasticsearch
by the principle of Separation of Duties.

As the application administrator (shown here as 'elasticsearch'), verify the
permissions for ES_HOME:

$ ls -la ${ES_HOME?}

If any files are not owned by the application owner or have permissions
allowing others to modify (write) configuration files, this is a finding."
  tag "fix": "As the system administrator, change the permissions of ES_HOME."
end
