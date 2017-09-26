only_if do
  service('elasticsearch').installed?
end

control "V-27137" do
  title "Applications utilized for integrity verification must detect
unauthorized changes to software and information."
  impact 0.5
  tag "nist": ["SI-7", "Rev_3"]
  tag "severity": "medium"
  tag "rid": "SV-34436r1_rule"
  tag "stig_id": "SRG-APP-000262"
  tag "cci": "CCI-001297"
  tag "check": "The AIDE package must be installed if it is to be available for
integrity checking.

Run the following command to determine if the aide package is installed:

$ rpm -q aide

If the package is not installed, this is a finding."
  tag "fix": "Install the AIDE package with the command:

$ sudo yum install aide"

  begin
    describe command('aide') do
      it { should exist}
    end

  rescue Exception => msg
    describe "Exception: #{msg}" do
      it { should be_nil}
    end
  end

end
