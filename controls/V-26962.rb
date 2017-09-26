control "V-26962" do
  title "The application must support the organizational requirements to
specifically prohibit or restrict the use of unauthorized functions, ports,
protocols, and/or services."
  desc  "Configure Elasticsearch to only use ports and protocols acceptable by
organization policies. Disable the HTTP, Thrift, or Transport protocols if they
are unused and verify that they are configured to bind only to acceptable
network devices on acceptable ports as documented in the system's security
plan."
  impact 0.5
  tag "nist": ["CM-7 b", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-34247r1_rule"
  tag "stig_id": "SRG-APP-000142"
  tag "cci": "CCI-000382"
  tag "check": "Check Elasticsearch.yml settings and existing IP filtering
rules to verify that only sepecific IP behind hardware/software 'Managed
access control points' are listed.

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

$ curl -h content_type:application-json    -XGET
'http://<elasticsearch>:9200/_cluster/settings'

If these configuration setting are disabled, or not pointing to the 'Managed
access control points', this is a finding. "
  tag "fix": "Note: The following instructions use the ES_HOME environment
variable. See supplementary content APPENDIX-XXX for
instructions on configuring ES_HOME.

To change the Managed access control points of the application, as the
application administrator, change the following setting in elasticsearch.conf:


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
