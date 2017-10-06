control "V-27065" do
  title "The application must only generate error messages that provide
information necessary for corrective actions without revealing
organizational-defined sensitive or potentially harmful information in error
logs and administrative messages that could be exploited."
  desc  "Limit the access of users and administrators to error logs and
verbatim error log messages whether it be in application provided user
interfaces or the actual Elasticsearch error log. Ensure production has an
appropriate logging information level and is not set to a level left over from
development. Secure error logs with OS level protections."
  impact 0.5
  tag "nist": ["SI-11 a", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-34360r1_rule"
  tag "gtitle": "SRG-APP-000266"
  tag "cci": "CCI-001312"
  tag "check": "Elasticsearch cannot support this requirement without
assistance from an external application, policy, or service."
  tag "fix": "Do not expose Elasticsearch directly to users, instead have an
application make requests on behalf of users. If this is not possible, have an
application to sanitize requests and responses from and to users."
end
