
only_if do
  service('elasticsearch').installed?
end


control "V-26882" do
  title "Applications must allocate audit record storage capacity."
  desc  "Provision adequate storage for audit records in an automated fashion
based upon capacity studies for production systems."
  impact 0.5
  tag "nist": ["AU-4", "Rev_3"]
  tag "severity": "medium"
  tag "rid": "SV-34162r1_rule"
  tag "gtitle": "SRG-APP-000072"
  tag "cci": "CCI-000137"
  tag "check": "Run the following command to determine if
/var/log/elasticsearch/audit is on its own partition or logical volume:

$ mount | grep 'on /var/log/elasticsearch/audit '

If /var/log/elasticsearch/audit has its own partition or volume group, a line
will be returned. If no line is returned, this is a finding."
  tag "fix": "Audit logs are stored in the /var/log/elasticsearch/audit
directory. Ensure that it has its own partition or logical volume at
installation time, or migrate it later using LVM. Make absolutely certain that
it is large enough to store all audit logs that will be created by the auditing
daemon."


  begin
    describe mount('/var/log/audit') do
      it { should be_mounted }
    end

  rescue Exception => msg
    describe do
      skip "Exception: #{msg}"
    end
  end
end
