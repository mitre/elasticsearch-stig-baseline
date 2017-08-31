control "V-26912" do
  title "Ensure Elasticsearch PKI validation meets organizational requirements."
  desc  "Configure the centralized authentication service to enforce
organization policies such as valid certification path, trusted anchor."
  impact 0.5
  tag "nist": ["IA-3 (2)", "Rev_3"]
  tag "severity": "medium"
  tag "rid": "SV-34192r1_rule"
  tag "cci": "CCI-000781"
  tag "check": "Perform client side certifications validation when setting TLS "
  tag "fix": "None"
end
