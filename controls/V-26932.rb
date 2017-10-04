control "V-26932" do
  title "The application must obscure feedback of authentication information
during the authentication process to protect the information from possible
exploitation/use by unauthorized individuals."
  desc  "Do not expose Elasticsearch directly to users, instead have an
application make requests on behalf of users. If this is not possible, have an
application to sanitize requests and responses from and to users."
  impact 0.5
  tag "nist": ["IA-6", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-34212r1_rule"
  tag "gtitle": "SRG-APP-000178"
  tag "cci": "CCI-000206"
  tag "check": "Elasticsearch cannot support this requirement without
assistance from an external application, policy, or service."
  tag "fix": "Do not expose Elasticsearch directly to users, instead have an
application make requests on behalf of users. If this is not possible, have an
application to sanitize requests and responses from and to users."
end
