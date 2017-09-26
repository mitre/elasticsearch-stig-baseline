only_if do
  service('elasticsearch').installed?
end

control "V-27160" do
  title "The application must protect audit information from unauthorized
deletion."
  desc  "Configure operating system protections for audit records such that the
records are not editable or deletable by Elasticsearch administrators and not
accessible by unauthorized users."
  impact 0.5
  tag "nist": ["AU-9", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-34459r1_rule"
  tag "stig_id": "SRG-APP-000120"
  tag "cci": "CCI-000164"
  tag "check": "The /var/log/elasticsearch/audit folder must have mode 0644 or
less permissive.

To check the permissions of /var/log/elasticsearch/audit, run the command:

 $ ls -l /var/log/elasticsearch/audit

If properly configured, the output should indicate the following permissions:
-rw-r--r-- If it does not, this is a finding."
  tag "fix": "To properly set the permissions of /var/log/elasticsearch/audit,
run the command:

$ sudo chmod 0644 /var/log/elasticsearch/audit  "

  begin
    describe file('/var/log/audit') do
      its('mode') { should cmp <= 0644}
    end

  rescue Exception => msg
    describe "Exception: #{msg}" do
      it { should be_nil}
    end
  end
end
