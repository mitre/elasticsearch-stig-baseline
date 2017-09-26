control "V-26830" do
  title "Applications must be able to function within separate processing
domains (virtualized systems), when specified, so as to enable finer-grained
allocation of user privileges."
  desc  "If desired, install Elasticsearch on virtual machines or other
container technology to further encapsulate the privileges and resources
allocated to the system"
  impact 0.5
  tag "nist": ["AC-6 (4)", "Rev_3"]
  tag "severity": "medium"
  tag "rid": "SV-34080r1_rule"
  tag "stig_id": "SRG-APP-000064"
  tag "cci": "CCI-000226"
  tag "check": "If organiziational required, install elasticsearch on virtual
machines or other container technology to further encapsulate the privileges
and resources allocated to the system."
  tag "fix": "Encapsulate elasticsearch to virtual resources as organiziational
required."
end
