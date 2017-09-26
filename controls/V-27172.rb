control "V-27172" do
  title "Applications must support organizational requirements to issue public
key certificates under an appropriate certificate policy or obtain public key
certificates under an appropriate certificate policy from an approved service
provider."
  desc  "Configure PKI authentication, TLS/SSL, IP filtering; which are key
features of X-Pack Security. This should ensure that authentication and
communication within Elasticsearch utilizes organizational attained
certificates."
  impact 0.5
  tag "nist": ["SC-17", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-34471r1_rule"
  tag "stig_id": "SRG-APP-000205"
  tag "cci": "CCI-001159"
  tag "check": "Application must obtain public key certificates from an
apporved service provider.

As the application administrator (usually elasticsearch), check the xpack.ssl
settings are set to approved public key certificates.

$cat elasticsearch.yml | grep xpack.ssl

xpack.ssl.key:                     <server_key>.key
xpack.ssl.certificate:             <server_certificate>.crt
xpack.ssl.certificate_authorities: [ <approved_ca>.crt' ]

If these certificates are not approved certificates, this is a finding.  "
  tag "fix": "Revoke trust in any certificates not issued by a DoD-approved
certificate authority.

Configure Elasticsearch to accept only DoD and DoD-approved PKI end-entity
certificates. Verify that xpack.ssl.certificate_authorities is pointing to the
trusted certificate authority from an approved service providoer.

See the official documentation for the complete  guide on establishing SSL
configuration: https://www.elastic.co/guide/en/x-pack/current/ssl-tls.html"

  begin
    describe yaml(ELASTICSEARCH_CONF) do
      its(['xpack.ssl.key']) { should_not be_nil }
      its(['xpack.ssl.certificate']) { should_not be_nil }
      its(['xpack.ssl.certificate_authorities']) { should_not be_nil }
    end

    describe command("openssl rsa -in #{yaml(ELASTICSEARCH_CONF)['xpack.ssl.key']} -check -noout") do
      its('stdout'){ should match /RSA key ok/ }
    end

    describe x509_certificate(yaml(ELASTICSEARCH_CONF)['xpack.ssl.certificate']) do
      it { should be_certificate }
      it { should be_valid }
    end

    if yaml(ELASTICSEARCH_CONF)['xpack.ssl.certificate_authorities'].is_a?(Array)
      yaml(ELASTICSEARCH_CONF)['xpack.ssl.certificate_authorities'].each do |cert|
        describe x509_certificate(cert) do
          it { should be_certificate }
          it { should be_valid }
        end
      end
    else
      describe x509_certificate(yaml(ELASTICSEARCH_CONF)['xpack.ssl.certificate_authorities']) do
        it { should be_certificate }
        it { should be_valid }
      end
    end

  rescue Exception => msg
    describe "Exception: #{msg}" do
      it { should be_nil}
    end
  end
end
