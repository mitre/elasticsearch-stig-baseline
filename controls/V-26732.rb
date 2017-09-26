control "V-26732" do
  title "Applications must support the organizational requirement to
automatically monitor on atypical usage of accounts."
  desc  "Utilize perimeter, application, centralized authentication, and
repository audit controls to audit the use of systems in real time with
sufficient context.  X-Pack Security audit controls should be enabled to audit
the defaults of all HTTP/S based access to Elasticsearch.  All applications
should use HTTP/S  rather than Elasticsearch transport protocol."
  impact 0.5
  tag "nist": ["AC-2 (5) (c)", "Rev_3"]
  tag "severity": "medium"
  tag "rid": "SV-33980r1_rule"
  tag "stig_id": "SRG-APP-000030"
  tag "cci": "CCI-001356"
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
  tag "fix": "Configure elasticsearch realms settings to point to organization
supported authentication mechanism to allow for monitoring of atypical account
usage.

See the official documentation for the instructions on realm configuration:
https://www.elastic.co/guide/en/x-pack/current/_how_authentication_works.html"
end
