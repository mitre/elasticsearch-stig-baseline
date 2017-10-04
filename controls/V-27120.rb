control "V-27120" do
  title "Applications must support organizational requirements to employ
cryptographic mechanisms to protect information in storage."
  desc  "If necessary, encrypt data stored by Elasticsearch at rest through the
use of operating system controlled, and hardware accelerating file system
encryption utilizing key management not governed by the data repository."
  impact 0.5
  tag "nist": ["MP-4 (1)", "Rev_3"]
  tag "severity": "medium"
  tag "rid": "SV-34417r1_rule"
  tag "gtitle": "SRG-APP-000188"
  tag "cci": "CCI-001019"
  tag "check": "Determine if encryption must be used to protect data on the
system. If encryption must be used and is not employed, this is a finding."
  tag "fix": "For automated/unattended installations, it is possible to use
Kickstart by adding the --encrypted and --passphrase= options to the definition
of each partition to be encrypted. For example, the following line would
encrypt the root partition:
part / --fstype=ext4 --size=100 --onpart=hda1 --encrypted
--passphrase=PASSPHRASE
Any PASSPHRASE is stored in the Kickstart in plaintext, and the Kickstart must
than be protected accordingly. Omitting the --passphrase= option from the
partition definition will cause the installer to pause and interactively ask
for the passphrase during installation.

Detailed information on encrypting partitions using LUKS can be found on the
Red Hat Documentation web site:
https://docs.redhat.com/docs/en-US/Red_Hat_Enterprise_Linux/7/html/Security_Guide/sec-Encryption.html"
end
