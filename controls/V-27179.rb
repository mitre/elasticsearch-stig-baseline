ES_SERVICE_NAME= attribute(
  'es_service_name',
  description: 'Name of Elasticsearch service',
  default: 'elasticsearch'
)

only_if do
  service(ES_SERVICE_NAME).installed?
end

control "V-27179" do
  title "The application must prevent the presentation of information system
management-related functionality at an interface utilized by general (i.e.,
non-privileged) users."
  desc  "Applicable - does not meet - not configurable, and does not meet the
requirement."
  impact 0.5
  tag "nist": ["SC-2 (1)", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-34478r1_rule"
  tag "gtitle": "SRG-APP-000212"
  tag "cci": "CCI-001083"
  tag "check": "Elasticsearch cannot support this requirement without
assistance from an external application, policy, or service."
  tag "fix": "Do not expose Elasticsearch directly to users, instead have an
application make requests on behalf of users. If this is not possible, have an
application to sanitize requests and responses from and to users.

Separate the access point and accounts used to administer Elasticsearch by
configuring different user interfaces and issuing separate administrative
accounts for the use of administrators taking administrative actions. Prevent
Administrative interfaces and accounts should not be used for
non-administrative actions by using X-Pack's RBAC to enforce separation of
duties. Audit and alert on the actions of administrator accounts to assure they
are not being used for non-administrative action."

  only_if do
    false
  end
end
