ELASTICSEARCH_CONF = attribute(
  'elasticsearch_conf',
  description: 'Path to elasticsearch.yaml',
  default: '/etc/elasticsearch/elasticsearch.yml'
)

ES_OWNER = attribute(
  'es_owner',
  description: 'Elasticsearch owner',
  default: 'elasticsearch'
  )

ES_GROUP = attribute(
  'es_group',
  description: 'Elasticsearch owner',
  default: 'elasticsearch'
  )


only_if do
  service('elasticsearch').installed?
end

control "V-27165" do
  title "The application must protect audit tools from unauthorized deletion."
  desc  "Configure operating system protections for audit records such that the
records are not editable or deletable by Elasticsearch administrators and not
accessible by unauthorized users. Move audit logs off of local machines and
backup to a audit log management system."
  impact 0.5
  tag "nist": ["AU-9", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-34464r1_rule"
  tag "stig_id": "SRG-APP-000123"
  tag "cci": "CCI-001495"
  tag "check": "The elasticsearch.yml file controls audit function for the
application. Protection of this file is critical for system security.

To check the ownership of elasticsearch.yml, run the command:

 $ ls -lL ES_HOME/elasticsearch.yml

If properly configured, the output should indicate the following owner:
elasticsearch If it does not, this is a finding.

The elasticsearch.yml must have mode 0640 or less permissive.

To check the permissions of elasticsearch.yml, run the command:

 $ ls -l ES_HOME/elasticsearch.yml

If properly configured, the output should indicate the following permissions:
-rw-r--r-- If it does not, this is a finding."
  tag "fix": "To properly set the owner of /etc/shadow, run the command:

$ sudo chown elasticsearch elasticsearch.yml    --           ##   TODO add text
around adding rule "

  begin
    describe file(ELASTICSEARCH_CONF) do
      its('owner') { should eq ES_OWNER }
      its('group') { should eq ES_GROUP }
      its('mode') { should cmp <= 0640 }
    end

  rescue Exception => msg
    describe "Exception: #{msg}" do
      it { should be_nil}
    end
  end
end
