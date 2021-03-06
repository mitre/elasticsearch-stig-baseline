ES_SERVICE_NAME= attribute(
  'es_service_name',
  description: 'Name of Elasticsearch service',
  default: 'elasticsearch'
)

only_if do
  service(ES_SERVICE_NAME).installed?
end

control "V-27128" do
  title "The application must terminate the network connection associated with
a communications session at the end of the session or after an
organizational-defined time period of inactivity."
  desc  "Elasticsearch does not have sessions that need to be timed out, but
configure Elasticsearch tcp socket keepalive settings to organizational
mandates. And configure applications to use an appropriate scroll api in the
_search API's for scroll time window to prevent bloat of server side resources."
  impact 0.0
  tag "nist": ["SC-10", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-34426r1_rule"
  tag "gtitle": "SRG-APP-000190"
  tag "cci": "CCI-001133"
  tag "check": "Elasticsearch meets this requirement through design and
implementation.

Elasticsearch provides communication through REST API calls and terminates all
session and network communication at the response of every call through a
network.  This is a permanent not a finding. "
  tag "fix": "This requirement is a permanent not a finding. No fix is
required."

  only_if do
    false
  end
end
