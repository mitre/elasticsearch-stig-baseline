control "V-26980" do
  title "Applications using multifactor authentication when accessing
privileged accounts via the network must provide one of the factors by a device
that is separate from the information system gaining access."
  desc  "Within X-Pack Security, a Custom Realm can be implemented that
fulfills multifactor authentication. Multifactor checks can be integrated
within the single custom realm."
  impact 0.5
  tag "nist": ["IA-2 (6)", "Rev_3"]
  tag "severity": "medium"
  tag "rid": "SV-34268r1_rule"
  tag "gtitle": "SRG-APP-000154"
  tag "cci": "CCI-000771"
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
end
