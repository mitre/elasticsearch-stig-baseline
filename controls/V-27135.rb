control "V-27135" do
  title "Applications must provide automated support for the management of
distributed security testing."
  desc  "Present the human readable, organizational defined security labels on
all information transmitted from Elasticsearch either in the original records
or information products derived from that information so that it can be
appropriately handled by other systems or as a derived dataset within
Elasticsearch"
  impact 0.5
  tag "nist": ["SI-6 (2)", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-34434r1_rule"
  tag "gtitle": "SRG-APP-000263"
  tag "cci": "CCI-001295"
  tag "check": "The JSON data models used by a system must maintain
denormalized or linked security labels and markings for information such that
the information can be used for safeguarding information. Data in transit is
protected via TLS. Utilize X-Pack Security's Field and Document Level Security
features to restrict access based on information within the document.

As the elasticsearch administrator, run the following CURL command:

$ curl -XGET  -H 'Content-Type: application/json' -u <TEST_USER> -p
<TEST_CREDENTIALS> https://<elasticsearch>:9200/_xpack/security/role

Review the role permissions, if any role is incorrect or provides access to
cluster configuration outside of administrative roles, this is a finding."
  tag "fix": "As a data owner, build a data model that is denormalized or
linked security labels and markings for information such that the information
can be used for distributed security testing.

See the official documentation for the complete  guide on authorization
configuration:
https://www.elastic.co/guide/en/x-pack/current/authorization.html"
end
