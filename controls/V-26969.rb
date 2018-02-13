ES_SERVICE_NAME= attribute(
  'es_service_name',
  description: 'Name of Elasticsearch service',
  default: 'elasticsearch'
)

only_if do
  service(ES_SERVICE_NAME).installed?
end

control "V-26969" do
  title "The application must support and must not impede organizational
requirements to conduct backups of system-level information contained in the
information system per organizational-defined frequency."
  desc  "This requirement is a permanent not a finding. No fix is required."
  impact 0.0
  tag "nist": ["CP-9 (b)", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-34256r1_rule"
  tag "gtitle": "SRG-APP-000146"
  tag "cci": "CCI-000537"
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
