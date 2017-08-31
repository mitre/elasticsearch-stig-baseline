control "V-26909" do
  title "Use an organization centralized authentication and authorization
service"
  desc  "Configure the Elasticsearch cluster to use a centralized
authentication and authorization service such as Active Directory or LDAP in
order to comply with organization defined management policies."
  impact 0.5
  tag "nist": ["IA-3", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-34189r1_rule"
  tag "stig_id": "SRG-APP-000158"
  tag "cci": "CCI-000778"
  tag "check": "$ ls -l LOGFILE"
  tag "fix": "$ ls -l LOGFILE"
end
