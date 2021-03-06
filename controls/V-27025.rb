ES_SERVICE_NAME= attribute(
  'es_service_name',
  description: 'Name of Elasticsearch service',
  default: 'elasticsearch'
)

only_if do
  service(ES_SERVICE_NAME).installed?
end

control "V-27025" do
  title "Applications must isolate security functions from non-security
functions by means of an isolation boundary (implemented via partitions and
domains) controlling access to and protecting the integrity of, the hardware,
software, and firmware that perform those security functions. The application
must isolate security functions from non-security functions."
  desc  "If desired, install Elasticsearch on virtual machines or other
container technology to further encapsulate the privileges and resources
allocated to the system"
  impact 0.5
  tag "nist": ["SC-3", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-34319r1_rule"
  tag "gtitle": "SRG-APP-000233"
  tag "cci": "CCI-001084"
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
