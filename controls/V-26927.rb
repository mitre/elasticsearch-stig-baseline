ELASTICSEARCH_CONF= attribute(
  'elasticsearch_conf',
  description: 'Path to elasticsearch.yaml',
  default: '/etc/elasticsearch/elasticsearch.yml'
)

only_if do
  service('elasticsearch').installed?
end

control "V-26927" do
  title "Ensure Elasticsearch PKI validation meets organizational requirements."
  desc  "Configure the centralized authentication service to enforce
organization policies such as valid certification path, trusted anchor,
certificate revocation lists."
  impact 0.5
  tag "nist": ["IA-5 (2) (a)", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-34207r1_rule"
  tag "stig_id": "SRG-APP-000175"
  tag "cci": "CCI-000185"
  tag "check": "Must perform manual verification of certificates paths using
3rd party tools, like OpenSSl verify function, described:
https://wiki.openssl.org/index.php/Manual:Verify(1)

If the certificate is not valid, this is a finding."
  tag "fix": "Obtain a new certificate from approved service provider. Perform
validation of the certifcate until the path is valid.

Update the certificates in elasticsearch.yml to the valid certificate

$vi elasticsearch.yml

xpack.ssl.key:                     <server_key>.key
xpack.ssl.certificate:             <server_certificate>.crt "

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
