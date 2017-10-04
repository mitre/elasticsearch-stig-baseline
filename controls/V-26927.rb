ELASTICSEARCH_CONF= attribute(
  'elasticsearch_conf',
  description: 'Path to elasticsearch.yaml',
  default: '/etc/elasticsearch/elasticsearch.yml'
)

only_if do
  service('elasticsearch').installed?
end

control "V-26927" do
  title "The application, when utilizing PKI-based authentication, must
validate certificates by constructing a certification path with status
information to an accepted trust anchor."
  desc  "Configure the centralized authentication service to enforce
organizational policies such as valid certification path, trusted anchor,
certificate revocation lists."
  impact 0.5
  tag "nist": ["IA-5 (2) (a)", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-34207r1_rule"
  tag "gtitle": "SRG-APP-000175"
  tag "cci": "CCI-000185"
  tag "check": "When using PKI-based authentication; the certificate path must
be validated.

$ cat config/elasticsearch.yml | grep -A 10 -B 6 'type: \\?pki'

 xpack:
  security:
    authc:
      realms:
        pki1:
          type: pki
          username_pattern: 'EMAILADDRESS=(.*?)(?:,|$)'
          certificate_authorities: <CA_PATH>
          truststore.path: <TS_PATH>

If these settings are not correct or missing, this is a finding.  "
  tag "fix": "Configure elasticsearch realms settings to point to
organizational supported authentication mechanism

See the official documentation for the instructions on realm configuration:
https://www.elastic.co/guide/en/x-pack/current/_how_authentication_works.html"
  begin
    describe yaml(ELASTICSEARCH_CONF) do
      its(['xpack.ssl.key']) { should_not be_nil }
      its(['xpack.ssl.certificate']) { should_not be_nil }
    end

    describe command("openssl rsa -in #{yaml(ELASTICSEARCH_CONF)['xpack.ssl.key']} -check -noout") do
      its('stdout'){ should match /RSA key ok/ }
    end

    describe x509_certificate(yaml(ELASTICSEARCH_CONF)['xpack.ssl.certificate']) do
      it { should be_certificate }
      it { should be_valid }
    end

  rescue Exception => msg
    describe "Exception: #{msg}" do
      it { should be_nil}
    end
  end
end
