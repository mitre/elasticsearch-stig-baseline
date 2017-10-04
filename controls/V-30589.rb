only_if do
  service('elasticsearch').installed?
end

control "V-30589" do
  title "The application must use cryptographic mechanisms to protect the
integrity of audit tools."
  desc  "Elasticsearch meets this requirement through design and
implementation.

Please refer to guidelines at
https://www.elastic.co/guide/en/elasticsearch/reference/master/rpm.html#rpm-key


Elasticsearch supports this requirement and cannot be configured to be out of
compliance. This is a permanent not a finding. "
  impact 0.0
  tag "nist": ["AU-9 (3)", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-40333r1_rule"
  tag "gtitle": "SRG-APP-000290"
  tag "cci": "CCI-001496"
  tag "check": "Elasticsearch meets this requirement through design and
implementation.

Please refer to guidelines at
https://www.elastic.co/guide/en/elasticsearch/reference/master/rpm.html#rpm-key


Elasticsearch supports this requirement and cannot be configured to be out of
compliance. This is a permanent not a finding. "
  tag "fix": "This requirement is a permanent not a finding. No fix is
required."

  only_if do
    false
  end
end
