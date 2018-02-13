ES_SERVICE_NAME= attribute(
  'es_service_name',
  description: 'Name of Elasticsearch service',
  default: 'elasticsearch'
)

only_if do
  service(ES_SERVICE_NAME).installed?
end

control "V-27171" do
  title "The application must validate the integrity of security attributes
exchanged between systems."
  desc  "The application controlled data model for security labels and markings
should be human readable and present in all stored and transferred data models."
  impact 0.0
  tag "nist": ["SC-16 (1)", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-34470r1_rule"
  tag "gtitle": "SRG-APP-000204"
  tag "cci": "CCI-001158"
  tag "check": "Elasticsearch meets this requirement through design and
implementation.

Elasticsearch supports this requirement and cannot be configured to be out of
compliance. This is a permanent not a finding. "
  tag "fix": "This requirement is a permanent not a finding. No fix is
required."

  only_if do
    false
  end
end
