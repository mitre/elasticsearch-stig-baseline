control "V-26943" do
  title "Applications must prevent the installation of organizational-defined
critical software programs not signed with a certificate that has been
recognized and approved by the organizational."
  desc  "Elastic components should be installed from approved and controlled
copies of the software only.  The binary hashes of the approved software (down
to the patch level) should be routinely check according to the policies of the
organizational."
  impact 0.5
  tag "nist": ["CM-5 (3)", "Rev_3"]
  tag "severity": "medium"
  tag "rid": "SV-34224r1_rule"
  tag "gtitle": "SRG-APP-000131"
  tag "cci": "CCI-000352"
  tag "check": "Elasticsearch, Inc. signs all of packages with the
Elasticsearch Signing Key (PGP key D88E42B4, available from
https://pgp.mit.edu) with fingerprint:

4609 5ACC 8548 582C 1A26 99A9 D27D 666C D88E 42B4

As the system owner, download and install the public signing key and verify the
package:

rpm --import https://artifacts.elastic.co/GPG-KEY-elasticsearch
rpm -K elasticsearch

Review the response, if it does not respond with md5 gpg OK, this is a finding."
  tag "fix": "Elastic components should be installed from approved and
controlled copies of the software only.

See the official documentation for RPM installation at:
https://www.elastic.co/guide/en/elasticsearch/reference/current/rpm.html"
end
