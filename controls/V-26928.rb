ELASTICSEARCH_CONF= attribute(
  'elasticsearch_conf',
  description: 'Path to elasticsearch.yml',
  default: '/etc/elasticsearch/elasticsearch.yml'
)

ES_SERVICE_NAME= attribute(
  'es_service_name',
  description: 'Name of Elasticsearch service',
  default: 'elasticsearch'
)

only_if do
  service(ES_SERVICE_NAME).installed?
end

control "V-26928" do
  title "The application, when using PKI-based authentication, must enforce
authorized access to the corresponding private key."
  desc  "Ensure PKI Private Key is stored with properly ACL on operating
system, and the storage disks are set up with encryption-at-rest."
  impact 0.5
  tag "nist": ["IA-5 (2) (b)", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-34208r1_rule"
  tag "gtitle": "SRG-APP-000176"
  tag "cci": "CCI-000186"
  tag "check": "When using PKI-based authentication, it is critical to enforce
authorized access.

$ cat config/elasticsearch.yml | grep -A 10 -B 6 'type: \\?pki'

 xpack:
  security:
    authc:
      realms:
        pki1:
          type: pki
          username_pattern: 'EMAILADDRESS=(.*?)(?:,|$)'
          certificate_authorities: <CA_PATH>
          truststore.path: <TS_PATH>

If these settings are not correct or missing, this is a finding.

To check the ownership of <CA_PATH>, run the command:

$ ls -lL <CA_PATH>

If properly configured, the output should indicate the following owner:
<APPLICATION_OWNER>. If it does not, this is a finding.

To check the ownership of <TS_PATH>, run the command:

$ ls -lL <CA_PATH>

If properly configured, the output should indicate the following owner:
<APPLICATION_OWNER>. If it does not, this is a finding.
   "
  tag "fix": "Set the owner of <CA_PATH> and <TS_PATH> to the application
owner.

Change the ownership of <CA_PATH> to <APPLICATION_OWNER>, run the following
command:

$ sudo chown <APPLICATION_OWNER> <CA_PATH>

Change the ownership of <TS_PATH> to <APPLICATION_OWNER>, run the following
command:

$ sudo chown <APPLICATION_OWNER> <TS_PATH> "

  begin
    describe yaml(ELASTICSEARCH_CONF) do
      its(['xpack','security','authc','realms']) { should_not be_nil }
    end

    describe.one do
      yaml(ELASTICSEARCH_CONF)['xpack','security','authc','realms'].each do |realm|
        describe realm.last do
          its (['type']) { should cmp 'pki' }
        end
      end unless yaml(ELASTICSEARCH_CONF)['xpack','security','authc','realms'].nil?
    end

    yaml(ELASTICSEARCH_CONF)['xpack','security','authc','realms'].each do |realm|
      if realm.last['type'].eql?('pki')
        describe realm.last do
          its (['order']) { should_not be_nil }
          its (['username_pattern']) { should_not be_nil }
        end
      end
    end unless yaml(ELASTICSEARCH_CONF)['xpack','security','authc','realms'].nil?

  rescue Exception => msg
    describe "Exception: #{msg}" do
      it { should be_nil}
    end
  end
end
