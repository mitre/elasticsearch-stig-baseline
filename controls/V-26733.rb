control "V-26733" do
  title "Service Oriented Architecture (SOA) based applications must
dynamically manage user privileges and associated access authorizations."
  desc  "Populate user metadata dynamically upon login and Implement templated
RBAC policies with X-Pack Security to reflect the dynamic attributes of users.
(https://www.elastic.co/guide/en/x-pack/current/field-and-document-access-control.html#templating-role-query)"
  impact 0.5
  tag "nist": ["AC-2 (6)", "Rev_3"]
  tag "severity": "medium"
  tag "rid": "SV-33981r1_rule"
  tag "gtitle": "SRG-APP-000031"
  tag "cci": "CCI-000020"
  tag "check": "To establish dynamic privilege controls, elasticsearch relies
on external authentication mechanism (LDAP, AD, PKI), time to live (cache.ttl),
and document/field level security.

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

The default cache.ttl is 20m.

As a data owner, you can verify that your data model holds fields that can be
used to assist in privilege management.

As the elasticsearch administrator, you can verify that roles exists that are
specific to data access, run the following CURL command:

$ curl -XGET  -H 'Content-Type: application/json' -u <TEST_USER> -p
<TEST_CREDENTIALS> https://localhost:9200/_xpack/security/role

Review the role permissions, if any role is incorrect or provides general
access to all data, this is a finding.

"
  tag "fix": "Configure elasticsearch realms settings to point to
organizational supported authentication mechanism to handle account termination
and notification.

See the official documentation for the instructions on realm configuration:
https://www.elastic.co/guide/en/x-pack/current/_how_authentication_works.html


As a data owner, update your data model to contain fields that can be used to
control user privileges.

See the officieal documentation for the instructions on document and field
level security:
https://www.elastic.co/guide/en/x-pack/current/field-and-document-access-control.html"
end
