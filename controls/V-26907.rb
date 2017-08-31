control "V-26907" do
  title "Enable secured communication to and within the Elasticsearch cluster"
  desc  "Configure PKI authentication, TLS/SSL, and cluster key features of
X-pack Security so that authentication and communication within Elasticsearch
is replay resistant."
  impact 0.5
  tag "nist": ["IA-2 (8)", "Rev_3"]
  tag "severity": "medium"
  tag "rid": "SV-34187r1_rule"
  tag "stig_id": "SRG-APP-000156"
  tag "cci": "CCI-000774"
  tag "check": "Check Elasticsearch.yml settings and existing IP filtering
rules to verify that only sepecific IP behind hardware/software \"Managed
access control points\" are listed.

As the application administrator (usually elasticsearch, check the
xpack.security.http.filter setting contains IP address(es) of the  \"Managed
access control points\":

$cat elasticsearch.yml | grep \"xpack.security.http.filter\", Verify all three
settings; xpack.security.http.filter.enabled: true;
xpack.security.http.filter.allow: \"Managed access control points\";
xpack.security.http.filter.deny: _all

As an elasticsearch administrator test; verify runtime environment within
_culster settings are set to \"{}\" OR Verify all three settings are
xpack.security.http.filter.enabled: true; xpack.security.http.filter.allow:
\"Managed access control points\"; xpack.security.http.filter.deny: _all

$curl -H 'Content-Type: application/json' -u <TEST_USER> -p <TEST_CREDENTIALS>
-XGET \"http://<elasticsearch>:9200/_cluster/settings\"

If these configuration setting are disabled, or not pointing to the \"Managed
access control points\", this is a finding. "
  tag "fix": "Implement protective measures when enforcing password encryption
for transmission.

 See the official documentation for the complete  guide on establishing SSL
configuration: https://www.elastic.co/guide/en/x-pack/current/ssl-tls.html"
end
