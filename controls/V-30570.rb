ELASTICSEARCH_CONF= attribute(
  'elasticsearch_conf',
  description: 'Path to elasticsearch.yml',
  default: '/etc/elasticsearch/elasticsearch.yml'
)

only_if do
  service('elasticsearch').installed?
end

control "V-30570" do
  title "The application must enforce requirements for remote connections to
the information system."
  desc  "Limit access inbound and outbound access to Elasticsearch over
networks using software and hardware firewall rules. Disable zen multicast
discovery, and enable unicast only to known elasticsearch cluster nodes."
  impact 0.5
  tag "nist": ["AC-17 e", "Rev_3"]
  tag "severity": "medium"
  tag "rid": "SV-40299r1_rule"
  tag "gtitle": "SRG-APP-000140"
  tag "cci": "CCI-000066"
  tag "check": "Verify that external authentication mechanism is in place,
LDAP, Active Directory, or PKI and verify auditing is setup.

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

If these settings are not correct or missing, this is a finding.  As the
application administrator (usually elasticsearch, check the
xpack.security.audit.outputs setting contains logfile by running the following:


$ cat config/elasticsearch.yml | grep xpack.security.audit.outputs

If this configuration setting is not present, this is a finding.

If this configuration setting does not contain logfile, this is a finding.     "
  tag "fix": "Configure elasticsearch realms settings to point to
organizational supported authentication mechanism

See the official documentation for the instructions on realm configuration:
https://www.elastic.co/guide/en/x-pack/current/_how_authentication_works.html


Configure elasticsearch audit settings to contain sufficient information to
monitor for unauthorized access.

See the official documentation for the instructions on audit configuration:
https://www.elastic.co/guide/en/x-pack/current/auditing.html"

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

    describe yaml(ELASTICSEARCH_CONF) do
      its(['xpack.security.audit.enabled']) { should eq true }
      its(['xpack.security.audit.outputs']) { should include 'logfile' }
      its(['xpack.security.audit.logfile.events.include']) { should match_array ES_INCLUDED_LOGEVENTS }
      its(['xpack.security.audit.logfile.events.exclude']) { should match_array ES_EXCLUDED_LOGEVENTS }
    end
    
  rescue Exception => msg
    describe "Exception: #{msg}" do
      it { should be_nil}
    end
  end
end
