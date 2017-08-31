control "V-26928" do
  title "Limit access to Private Key through operating system controls"
  desc  "Ensure PKI Private Key is stored with properly ACL on operating
system, and the storage disks are setup with encryption-at-rest."
  impact 0.5
  tag "nist": ["IA-5 (2) (b)", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-34208r1_rule"
  tag "stig_id": "SRG-APP-000176"
  tag "cci": "CCI-000186"
  tag "check": "Root owned?  I would assume you cannot run the application as
elasticsearch, but have the certs owned by Root, and not reablable by
elasticsearch."
  tag "fix": "None"
end
