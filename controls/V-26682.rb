control "V-26682" do
  title "Encrypt information in transit both at the Elasticsearch perimeter and within
	the Elasticsearch cluster
	"
  desc  "
    Use SSL / TLS communication for all networked access to Elasticsearch and
    connected components such as Kibana and Logstash.  X-Pack Security should be
    configured with organization approved cryptography.

  "
  impact 0.5
  tag "severity": "medium"
  tag "rid": "SV-33882r1_rule"
  tag "stig_id": "SRG-APP-000015"
  tag "cci": "CCI-001453"
  tag "nist": ["AC-17 (2)", "Rev_4"]
  tag "check": "Application must utilize approved cryptography to protect remote access
	sessions.

	As the application administrator (usually elasticsearch),
	check the xpack.ssl settings are set to the correct values.

	$cat
	elasticsearch.yml | grep xpack.ssl

	xpack.ssl.key:
	<server_key>.key
	xpack.ssl.certificate:             <server_certificate>.crt
	xpack.ssl.certificate_authorities: [ <approved_ca>.crt\" ]

	If these
	setting are not set or the underlining certificate and keys are not correct,
	this is a finding.

	$cat elasticsearch.yml | grep
	xpack.security.http.ssl.enabled: true

	If this setting is not present or set
	to true, this is a finding.

	As a elasticsearch user, check that non-secure
	http traffic does not response with 200 status:

	$curl
	http://<elasticsearchIP:9200>/

	If a 200 response comes back, this is a
	finding.
	"
  tag "fix": "Implement protective measures when providing remote access.

	See
	the official documentation for the complete  guide on establishing SSL
	configuration: https://www.elastic.co/guide/en/x-pack/current/ssl-tls.html
	"
end
