ELASTICSEARCH_CONF= attribute(
  'elasticsearch_conf',
  description: 'Path to elasticsearch.yml',
  default: '/etc/elasticsearch/elasticsearch.yml'
)

only_if do
  service('elasticsearch').installed?
end

control "V-26853" do
  title "Applications must have the capability to limit the number of failed
login attempts based upon an organizational defined number of consecutive
invalid attempts occurring within an organizational defined time period."
  desc  "Configure the centralized authentication service to enforce
organizational policies such as password strength, lockout, expiration,
notification, and screen obfuscation."
  impact 0.5
  tag "nist": ["AC-7 a", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-34133r1_rule"
  tag "gtitle": "SRG-APP-000065"
  tag "cci": "CCI-000044"
  tag "check": "Guidance in Appendix B - System accounts cannot be disabled and
elasticsearch does not enforce password complexity rules.

Elasticsearch supports LDAP, Active Directory, and PKI.

If the external authentication is Active Directory; verify the following
settings.

$ cat config/elasticsearch.yml | grep -A 6 -B 6 'type: \\?active_directory'


 xpack:
  security:
    authc:
      realms:
        active_directory:
          type: active_directory
          order: 0
          domain_name: ad.example.com
          url: ldaps://ad.example.com:636
          unmapped_groups_as_roles: true | false

If these settings are not correct or missing, this is a finding.

If the external authentication is LDAP; verify the following settings.

$ cat config/elasticsearch.yml | grep -A 16 -B 6 'type: \\?ldap'

xpack:
  security:
    authc:
      realms:
        ldap1:
          type: ldap
          order: 0
          url: 'ldaps://ldap.example.com:636'
          bind_dn: 'cn=ldapuser, ou=users, o=services, dc=example, dc=com'
          bind_password: changeme
          user_search:
            base_dn: 'dc=example,dc=com'
            attribute: cn
          group_search:
            base_dn: 'dc=example,dc=com'
          files:
            role_mapping: 'CONFIG_DIR/x-pack/role_mapping.yml

If these settings are not correct or missing, this is a finding.

If the external authentication is PKI; verify the following settings.

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

    yaml(ELASTICSEARCH_CONF)['xpack','security','authc','realms'].each do |realm|
      if realm.last['type'].eql?('active_directory')
        describe realm.last do
          its (['order']) { should_not be_nil }
          its (['domain_name']) { should_not be_nil }
          its (['url']) { should_not be_nil }
          its (['unmapped_groups_as_roles']) { should_not be_nil }
        end
      end
      if realm.last['type'].eql?('ldap')
        describe realm.last do
          its (['order']) { should_not be_nil }
          its (['url']) { should_not be_nil }
          its (['bind_dn']) { should_not be_nil }
          its (['bind_password']) { should_not be_nil }
          its (['user_search','base_dn']) { should_not be_nil }
          its (['user_search','attribute']) { should_not be_nil }
          its (['group_search','base_dn']) { should_not be_nil }
          its (['files','role_mapping']) { should_not be_nil }
        end
      end
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

