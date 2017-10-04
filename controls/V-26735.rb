control "V-26735" do
  title "The application must enforce approved authorizations for logical
access to the system in accordance with applicable policy."
  desc  "Plan for granting temporary authorizations, with known automated
expiration times, to enable users to implement out of the ordinary processes."
  impact 0.5
  tag "nist": ["AC-3", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-33983r1_rule"
  tag "gtitle": "SRG-APP-000033"
  tag "cci": "CCI-000213"
  tag "check": "Verify that role-based policies are in place and access
enforcement mechanisms are in place.

As the elasticsearch administrator, run the following CURL command:

$ curl -XGET  -H 'Content-Type: application/json' -u <TEST_USER> -p
<TEST_CREDENTIALS> https://<elasticsearch>:9200/_xpack/security/role

Review the role permissions, if any role is incorrect or provides access to
cluster configuration outside of administrative roles, this is a finding.

Check Elasticsearch.yml settings and existing IP filtering rules to verify that
only specific IP behind hardware/software 'Managed access control points'
are listed.

As the application administrator (usually elasticsearch, check the
xpack.security.http.filter setting contains IP address(es) of the  'Managed
access control points':

$cat elasticsearch.yml | grep 'xpack.security.http.filter', Verify all three
settings; xpack.security.http.filter.enabled: true;
xpack.security.http.filter.allow: 'Managed access control points';
xpack.security.http.filter.deny: _all

As an elasticsearch administrator test; verify runtime environment within
_culster settings are set to '{}' OR Verify all three settings are
xpack.security.http.filter.enabled: true; xpack.security.http.filter.allow:
'Managed access control points'; xpack.security.http.filter.deny: _all

$curl -H 'Content-Type: application/json' -u <TEST_USER> -p <TEST_CREDENTIALS>
 -XGET 'http://<elasticsearch>:9200/_cluster/settings'

If these configuration setting are disabled, or not pointing to the 'Managed
access control points', this is a finding. "
  tag "fix": "Implement strong access controls to secure application data by
establishing role-based policies and access control mechanisms.

To establish role-based policies; see the official documentation on
authorization;
https://www.elastic.co/guide/en/x-pack/current/authorization.html.

Note: The following instructions use the ES_HOME environment variable. See
supplementary content APPENDIX-XXX for instructions on configuring ES_HOME.

To establish an access control mechanism; as the application administrator,
change the following setting in elasticsearch.yml:

$ sudo su - elasticsearch
$ vi $ES_HOME/config/elasticsearch.yml

Change the Managed access control points parameter to the desired addresses,
i.e.:
     xpack.security.http.filter.enabled: true
     xpack.security.http.filter.allow: 'Managed access control points'
     xpack.security.http.filter.deny: _all

Next, restart the application:
$ sudo su - elasticsearch

# SYSTEMD SERVER ONLY
$ systemctl restart elasticsearch"
end
