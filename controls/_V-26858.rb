control "V-26858" do
  title "Approved System Use notification"
  desc  "Create a HA proxy static page that shows System Usage notification"
  impact 0.5
  tag "nist": ["AC-8 a", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-34138r1_rule"
  tag "stig_id": "SRG-APP-000068"
  tag "cci": "CCI-000048"
  tag "check": "Possible not applicable because of server to service
communcation, when user login vai LDAP/AD you may show banner in Kibana.
Dependant on user service, When using kibana - set this prooperty.  For
elasticsearch during service connection "
  tag "fix": "None"
end
