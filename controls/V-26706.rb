ELASTICSEARCH_CONF= attribute(
  'elasticsearch_conf',
  description: 'Path to elasticsearch.yml',
  default: '/etc/elasticsearch/elasticsearch.yml'
)

only_if do
  service('elasticsearch').installed?
end

control "V-26706" do
  title "Applications must support the requirement to automatically audit
account modification."
  desc  "Utilize perimeter, application, centralized authentication, and
repository audit controls to audit the use of systems in real time with
sufficient context.  X-Pack Security audit controls should be enabled to audit
the defaults of all HTTP/S based access to Elasticsearch.  All applications
should use HTTP/S  rather than Elasticsearch transport protocol."
  impact 0.5
  tag "nist": ["AC-2 (4)", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-33949r1_rule"
  tag "gtitle": "SRG-APP-000027"
  tag "cci": "CCI-001403"
  tag "check": "Account termination and notification must be handled by an one
of the supported external authentication mechanism; LDAP, Active Directory, or
PKI and verify auditing is setup.

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
organizational supported authentication mechanism to handle account
modification auditing.

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

  rescue Exception => msg
    describe "Exception: #{msg}" do
      it { should be_nil}
    end
  end
end
