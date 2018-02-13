ES_SERVICE_NAME= attribute(
  'es_service_name',
  description: 'Name of Elasticsearch service',
  default: 'elasticsearch'
)

only_if do
  service(ES_SERVICE_NAME).installed?
end

control "V-27146" do
  title "Applications must use internal system clocks to generate time stamps
for audit records."
  desc  "Utilize perimeter, application, centralized authentication, and
repository audit controls to audit the use of systems in real time with
sufficient context.  X-Pack Security audit controls should be enabled to audit
the defaults of all HTTP/S based access to Elasticsearch.  All applications
should use HTTP/S  rather than Elasticsearch transport protocol."
  impact 0.0
  tag "nist": ["AU-8 a", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-34445r1_rule"
  tag "gtitle": "SRG-APP-000116"
  tag "cci": "CCI-000159"
  tag "check": "The Elasticsearch application's auditing system supports this
requirement and cannot be configured to be out of compliance. Every audit
record in elasticsearch includes a timestamp.

This is a permanent not a finding."
  tag "fix": "This requirement is a permanent not a finding. No fix is
required."

  only_if do
    false
  end
end
