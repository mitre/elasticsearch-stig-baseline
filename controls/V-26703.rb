control "V-26703" do
  title "The application must be capable of automatically disabling accounts
after a 35 day period of account inactivity."
  desc  "Configure the X-Pack Security to use a centralized authentication and
authorization service such as Active Directory or LDAP in order to comply with
organizational defined management policies."
  impact 0.5
  tag "nist": ["AC-2 (3)", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-33946r1_rule"
  tag "gtitle": "SRG-APP-000025"
  tag "cci": "CCI-000017"
  tag "check": "Account disabling must be handled by an one of the supported
external authentication mechanism; LDAP, Active Directory, or PKI.

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
organizational supported authentication mechanism to handle account disabling.

See the official documentation for the instructions on realm configuration:
https://www.elastic.co/guide/en/x-pack/current/_how_authentication_works.html "
end
