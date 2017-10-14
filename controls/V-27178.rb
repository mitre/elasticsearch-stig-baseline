only_if do
  service('elasticsearch').installed?
end

control "V-27178" do
  title "The application must separate user functionality (including user
interface services) from information system management functionality."
  desc  "Applicable - does not meet - not configurable, and does not meet the
requirement."
  impact 0.5
  tag "nist": ["SC-2", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-34477r1_rule"
  tag "gtitle": "SRG-APP-000211"
  tag "cci": "CCI-001082"
  tag "check": "Elasticsearch cannot support this requirement without
assistance from an external application, policy, or service."
  tag "fix": "Integrating a Proxy or API gateway in front of elasticsearch REST
API will allow you to separate user functions from system management functions.


This is different than Access to the system management functions, as the access
can be controlled by X-Pack Role based Access Controls."

  only_if do
    false
  end
end
