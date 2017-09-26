control "V-27178" do
  title "The application must separate user functionality (including user
interface services) from information system management functionality."
  impact 0.5
  tag "nist": ["SC-2", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-34477r1_rule"
  tag "stig_id": "SRG-APP-000211"
  tag "cci": "CCI-001082"
  tag "check": "Elasticsearch cannot support this requirement without
assistance from an external application, policy, or service."
  tag "fix": "Integrating a Proxy or API gateway in front of elasticsearch REST
API will allow you to seperate user functions from system management functions.


This is different then Access to the system managemnet functions, as the access
can be controlled by X-Pack Role based Access Controls."
end