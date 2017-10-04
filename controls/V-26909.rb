control "V-26909" do
  title "Applications required to identify devices must uniquely identify and
authenticate an organizational-defined list of specific and/or types of devices
before establishing a connection."
  desc  "Configure the Elasticsearch cluster to use a centralized
authentication and authorization service such as Active Directory or LDAP in
order to comply with organizational defined management policies."
  impact 0.5
  tag "nist": ["IA-3", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-34189r1_rule"
  tag "gtitle": "SRG-APP-000158"
  tag "cci": "CCI-000778"
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
end
