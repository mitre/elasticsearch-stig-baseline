only_if do
  service('elasticsearch').installed?
end

control "V-27137" do
  title "Applications utilized for integrity verification must detect
unauthorized changes to software and information."
  desc  "Applicable - does not meet - not configurable, and does not meet the
requirement."
  impact 0.5
  tag "nist": ["SI-7", "Rev_3"]
  tag "severity": "medium"
  tag "rid": "SV-34436r1_rule"
  tag "gtitle": "SRG-APP-000262"
  tag "cci": "CCI-001297"
  tag "check": "Elasticsearch cannot support this requirement without
assistance from an external application, policy, or service."
  tag "fix": "The AIDE package can be installed to be available for integrity
checking.

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
