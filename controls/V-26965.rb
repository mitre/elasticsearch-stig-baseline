ES_SERVICE_NAME= attribute(
  'es_service_name',
  description: 'Name of Elasticsearch service',
  default: 'elasticsearch'
)

only_if do
  service(ES_SERVICE_NAME).installed?
end

control "V-26965" do
  title "Applications must implement transaction recovery for systems that are
transaction-based."
  desc  "Elasticsearch utilizes a transaction log to ensure the writes are
recorded during crash and can be replayed during a recovery phase."
  impact 0.0
  tag "nist": ["CP-10 (2)", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-34250r1_rule"
  tag "gtitle": "SRG-APP-000144"
  tag "cci": "CCI-000553"
  tag "check": "Elasticsearch utilizes a transaction log to ensure the writes
are recorded during crash and can be replayed during a recovery phase.

This is a permanent not a finding."
  tag "fix": "This requirement is a permanent not a finding. No fix is
required."

  only_if do
    false
  end
end

