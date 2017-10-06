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

control "V-26887" do
  title "Applications must configure their auditing to reduce the likelihood of
storage capacity being exceeded."
  desc  "Offload and centralize audit records retention to a separate system
from the sources of audit records."
  impact 0.5
  tag "nist": ["AU-4", "Rev_3"]
  tag "severity": "medium"
  tag "rid": "SV-34167r1_rule"
  tag "gtitle": "SRG-APP-000071"
  tag "cci": "CCI-000138"
  tag "check": "Check Elasticsearch.yml settings and existing audit records to
verify information specific to the necessary content of the event is being
captured and stored with audit records.

As the application administrator (usually elasticsearch, check the
xpack.security.audit.outputs setting contains logfile by running the following:


$ cat config/elasticsearch.yml | grep xpack.security.audit

This setting allows for the customization of audits to reduce likelihood of
exceeding storage capacity.

For a complete list of extra information that can be added to log_line_prefix,
see the official documentation:
https://www.elastic.co/guide/en/x-pack/current/auditing.html      "
  tag "fix": "Configure elasticsearch audit settings to contain sufficient
information to establish where an event occurred.

See the official documentation for the instructions on audit configuration:
https://www.elastic.co/guide/en/x-pack/current/auditing.html

If javascript or python plugins are installed on the machine; run uninstall
command as follows:"

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
