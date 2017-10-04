control "V-27027" do
  title "Applications must meet organizational requirements to implement an
information system isolation boundary that minimizes the number of non-security
functions included within the boundary containing security functions."
  desc  "If desired, install Elasticsearch on virtual machines or other
container technology to further encapsulate the privileges and resources
allocated to the system"
  impact 0.5
  tag "nist": ["SC-3 (3)", "Rev_3"]
  tag "severity": "medium"
  tag "rid": "SV-34321r1_rule"
  tag "gtitle": "SRG-APP-000236"
  tag "cci": "CCI-001087"
  tag "check": "If organizational required, install elasticsearch on virtual
machines or other container technology to further encapsulate the privileges
and resources allocated to the system."
  tag "fix": "Encapsulate elasticsearch to virtual resources as organizational
required."
end
