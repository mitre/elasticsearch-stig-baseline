only_if do
  service('elasticsearch').installed?
end

control "V-27029" do
  title "Applications must meet organizational requirements to implement
security functions as a layered structure minimizing interactions between
layers of the design and avoiding any dependence by lower layers on the
functionality or correctness of higher layers."
  desc  "If desired, install Elasticsearch on virtual machines or other
container technology to further encapsulate the privileges and resources
allocated to the system"
  impact 0.5
  tag "nist": ["SC-3 (5)", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-34323r1_rule"
  tag "gtitle": "SRG-APP-000238"
  tag "cci": "CCI-001089"
  tag "check": "If organizational required, install elasticsearch on virtual
machines or other container technology to further encapsulate the privileges
and resources allocated to the system."
  tag "fix": "Encapsulate elasticsearch to virtual resources as organizational
required."

  begin
    describe virtualization do
      its('role') { should eq 'guest' }
    end

  rescue Exception => msg
    describe "Exception: #{msg}" do
      it { should be_nil}
    end
  end
end
