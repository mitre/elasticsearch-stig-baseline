control "V-26827" do
  title "Application users must utilize a separate, distinct administrative
account when accessing application security functions or security-relevant
information. Non-privileged accounts must be utilized when accessing
non-administrative application functions. The application must provide this
functionality itself or leverage an existing technology providing this
capability."
  desc  "Separate the access point and accounts used to administer
Elasticsearch by configuring different user interfaces and issuing separate
administrative accounts for the use of administrators taking administrative
actions. Prevent Administrative interfaces and accounts should not be used for
non-administrative actions by using X-Pack's RBAC to enforce separation of
duties. Audit and alert on the actions of administrator accounts to assure they
are not being used for non-administrative action."
  impact 0.5
  tag "nist": ["AC-6 (2)", "Rev_3"]
  tag "severity": "medium"
  tag "rid": "SV-34077r1_rule"
  tag "gtitle": "SRG-APP-000063"
  tag "cci": "CCI-000040"
  tag "check": "Guidance in Appendix B - System accounts cannot be disabled and
elasticsearch does not enforce password complexity rules.

For all other accounts, admin and non-administrative should be handled
externally by LDAP, Active Directory, and PKI.

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
