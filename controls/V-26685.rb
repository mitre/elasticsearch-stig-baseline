control "V-26685" do
  title "Control network access to Elasticsearch
	"
  desc  "
    Limit network access to Elasticsearch software from known points of origin
    with the use of software and hardware firewalls as well as X-Pack Security IP
    Filtering. Change the elasticsearch cluster name to an instance unique value
    for all elasticsearch nodes and all applications should use HTTP/S  rather
    than Elasticsearch transport protocol.

  "
  impact 0.5
  tag "severity": "medium"
  tag "rid": "SV-33908r1_rule"
  tag "stig_id": "SRG-APP-000017"
  tag "cci": "CCI-000069"
  tag "nist": ["AC-17 (3)", "Rev_4"]
  tag "check": "Check Elasticsearch.yml settings and existing IP filtering rules to verify
	that only sepecific IP behind hardware/software \"Managed access control
	points\" are listed.

	As the application administrator (usually
	elasticsearch, check the xpack.security.http.filter setting contains IP
	address(es) of the  \"Managed access control points\":

	$cat elasticsearch.yml
	| grep \"xpack.security.http.filter\", Verify all three settings;
	xpack.security.http.filter.enabled: true; xpack.security.http.filter.allow:
	\"Managed access control points\"; xpack.security.http.filter.deny: _all

	As an
	elasticsearch administrator test; verify runtime environment within _culster
	settings are set to \"{}\" OR Verify all three settings are
	xpack.security.http.filter.enabled: true; xpack.security.http.filter.allow:
	\"Managed access control points\"; xpack.security.http.filter.deny: _all

	$ curl
	-h content_type:application-json    -XGET
	\"http://<elasticsearch>:9200/_cluster/settings\"

	If these configuration
	setting are disabled, or not pointing to the \"Managed access control points\",
	this is a finding.
	"
  tag "fix": "Note: The following instructions use the ESHOME environment variable. See
	supplementary content APPENDIX-XXX for
	instructions on configuring ESHOME.

	To
	change the Managed access control points of the application, as the
	application administrator, change the following setting in elasticsearch.conf:
	$ sudo su - elasticsearch
	$ vi $ESHOME/config/elasticsearch.yml

	Change the
	Managed access control points parameter to the desired addresses, i.e.:

	xpack.security.http.filter.enabled: true

	xpack.security.http.filter.allow: \"Managed access control points\"

	xpack.security.http.filter.deny: _all

	Next, restart the
	application:
	$ sudo su - elasticsearch

	# SYSTEMD SERVER ONLY
	$ systemctl
	restart elasticsearch
	"
end
