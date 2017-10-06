ELASTICSEARCH_CONF = attribute(
  'elasticsearch_conf',
  description: 'Path to elasticsearch.yaml',
  default: '/etc/elasticsearch/elasticsearch.yml'
)

ES_INCLUDED_LOGEVENTS = attribute(
  'es_included_logevents',
  description: 'List of events to be logged',
  default: ['access_denied', 'anonymous_access_denied', 'authentication_failed',
     'connection_denied', 'tampered_request', 'run_as_denied', 'run_as_granted']
)

ES_EXCLUDED_LOGEVENTS = attribute(
  'es_included_logevents',
  description: 'List of events to be logged',
  default: ['access_granted']
)

only_if do
  service('elasticsearch').installed?
end

control "V-26906" do
  title "The application must provide the capability to remotely view/hear all
content related to an established user session in real time."
  desc  "Utilize perimeter, application, centralized authentication, and
repository audit controls to audit the use of systems in real time with
sufficient context.  X-Pack Security audit controls should be enabled to audit
the defaults of all HTTP/S based access to Elasticsearch.  All applications
should use HTTP/S  rather than Elasticsearch transport protocol."
  impact 0.5
  tag "nist": ["AU-14 b", "Rev_3"]
  tag "severity": "medium"
  tag "rid": "SV-34186r1_rule"
  tag "gtitle": "SRG-APP-000094"
  tag "cci": "CCI-001463"
  tag "check": "Check Elasticsearch.yml settings and existing audit records to
verify information specific to the necessary content of the event is being
captured and stored with audit records.

As the application administrator (usually elasticsearch, check the
xpack.security.audit.outputs setting contains logfile by running the following:


$ cat config/elasticsearch.yml | grep xpack.security.audit.outputs

If this configuration setting is not present, this is a finding.  If this
configuration setting does not contain logfile, this is a finding.

For a complete list of extra information that can be added to log_line_prefix,
see the official documentation:
https://www.elastic.co/guide/en/x-pack/current/auditing.html

 If the current settings do not provide enough information regarding the
content of the event, this is a finding."
  tag "fix": "Configure elasticsearch audit settings to contain sufficient
information to establish the outcome of an event occurred.

See the official documentation for the instructions on audit configuration:
https://www.elastic.co/guide/en/x-pack/current/auditing.html"

  begin
    describe yaml(ELASTICSEARCH_CONF) do
      its(['xpack.security.audit.enabled']) { should eq true }
      its(['xpack.security.audit.outputs']) { should include 'logfile' }
      its(['xpack.security.audit.logfile.events.include']) { should match_array ES_INCLUDED_LOGEVENTS }
      its(['xpack.security.audit.logfile.events.exclude']) { should match_array ES_EXCLUDED_LOGEVENTS }
    end

  rescue Exception => msg
    describe do
      skip "Exception: #{msg}"
    end
  end
  
end
