control "V-26928" do
  title "The application, when using PKI-based authentication, must enforce
authorized access to the corresponding private key."
  desc  "Ensure PKI Private Key is stored with properly ACL on operating
system, and the storage disks are setup with encryption-at-rest."
  impact 0.5
  tag "nist": ["IA-5 (2) (b)", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-34208r1_rule"
  tag "stig_id": "SRG-APP-000176"
  tag "cci": "CCI-000186"
  tag "check": "When using PKI-basd authentication, it is critical to enforce
authorized access.

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

If these settings are not correct or missing, this is a finding.

To check the ownership of <CA_PATH>, run the command:

$ ls -lL <CA_PATH>

If properly configured, the output should indicate the following owner:
<APPLICATION_OWNER>. If it does not, this is a finding.

To check the ownership of <TS_PATH>, run the command:

$ ls -lL <CA_PATH>

If properly configured, the output should indicate the following owner:
<APPLICATION_OWNER>. If it does not, this is a finding.
   "
  tag "fix": "Set the owner of <CA_PATH> and <TS_PATH> to the application
owner.

Change the ownership of <CA_PATH> to <APPLICATION_OWNER>, run the following
command:

$ sudo chown <APPLICATION_OWNER> <CA_PATH>

Change the ownership of <TS_PATH> to <APPLICATION_OWNER>, run the following
command:

$ sudo chown <APPLICATION_OWNER> <TS_PATH> "
end
