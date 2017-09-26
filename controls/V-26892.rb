control "V-26892" do
  title "The application must provide a real-time alert when
organization-defined audit failure events occur."
  desc  "Offload and centralize audit records retention to a separate system
from the sources of audit records."
  impact 0.5
  tag "nist": ["AU-5 (2)", "Rev_3"]
  tag "severity": "medium"
  tag "rid": "SV-34172r1_rule"
  tag "stig_id": "SRG-APP-000104"
  tag "cci": "CCI-000144"
  tag "check": "The necessary monitoring and alerts may be implemented using
features of elasticsearch, the OS, third-party software, custom code, or a
combination of these. The term 'the system' is used to encompass all of
these.

Review the system documentation to determine which audit failure events require
real-time alerts. Review the system settings and code.

If the real-time alerting that is specified in the documentation is not
enabled, this is a finding."
  tag "fix": "Configure the system to provide an immediate real-time alert to
appropriate support staff when a specified audit failure occurs.

It is possible to create scripts or implement third-party tools to enable
real-time alerting for audit failures in elasticsearch."

  only_if do
    false
  end
end
