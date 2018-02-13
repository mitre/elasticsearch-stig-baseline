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

control "V-26978" do
  title "The application must use multifactor authentication for local access
to non-privileged accounts."
  desc  "Within X-Pack Security, a Custom Realm can be implemented that
fulfills multifactor authentication. Multifactor checks can be integrated
within the single custom realm."
  impact 0.5
  tag "nist": ["IA-2 (4)", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-34266r1_rule"
  tag "gtitle": "SRG-APP-000152"
  tag "cci": "CCI-000768"
  tag "check": "Guidance in Appendix B - System accounts cannot be disabled and
elasticsearch does not enforce multifactor authentication.

Elasticsearch only supports PKI for multifactor authentication; to ensure PKI
is enabled, verify the following settings.

$ cat config/elasticsearch.yml | grep -A 6 -B 6 'type: \\?pki'

 xpack:
  security:
    authc:
      realms:
        pki1:
          type: pki
          username_pattern: 'EMAILADDRESS=(.*?)(?:,|$)'

If these settings are not correct or missing, this is a finding.

"
  tag "fix": "Configure elasticsearch realms settings to point to
organizational supported authentication mechanism

See the official documentation for the instructions on realm configuration:
https://www.elastic.co/guide/en/x-pack/current/_how_authentication_works.html"

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
