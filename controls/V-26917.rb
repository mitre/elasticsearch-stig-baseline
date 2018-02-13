ES_SERVICE_NAME= attribute(
  'es_service_name',
  description: 'Name of Elasticsearch service',
  default: 'elasticsearch'
)

only_if do
  service(ES_SERVICE_NAME).installed?
end

control "V-26917" do
  title "The application must enforce configurable traffic volume thresholds
representing auditing capacity for network traffic."
  desc  "Applicable - does not meet - not configurable, and does not meet the
requirement."
  impact 0.5
  tag "nist": ["AU-5 (3)", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-34197r1_rule"
  tag "gtitle": "SRG-APP-000105"
  tag "cci": "CCI-000145"
  tag "check": "Elasticsearch cannot support this requirement without
assistance from an external application, policy, or service."
  tag "fix": "Integrate network traffic control solutions outside of
elasticsearch.  Monitor the health and resources (such as remaining storage) of
systems running Elasticsearch software and notify operators when safety
thresholds have been exceeded. "

  only_if do
    false
  end
end
