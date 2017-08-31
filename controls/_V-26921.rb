control "V-26921" do
  title "Ensure Elasticsearch passwords and credentials meet organizational
requirements."
  desc  "Configure the centralized authentication service to enforce
organization policies such as password strength, lockout, expiration,
notification, and screen obfuscation."
  impact 0.5
  tag "nist": ["IA-5 (1) (a)", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-34201r1_rule"
  tag "stig_id": "SRG-APP-000169"
  tag "cci": "CCI-001619"
  tag "check": "None ()ELasticsearch supports LDAP, AD, and PKI, if you use AD
verify these are set -   xpack:
  security:
    authc:
      realms:
        active_directory:
          type: active_directory
          order: 0
          domain_name: ad.example.com
          url: ldaps://ad.example.com:636
          unmapped_groups_as_roles: true "
  tag "fix": "None"
end
