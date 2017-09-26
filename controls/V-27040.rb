control "V-27040" do
  title "Applications must manage excess capacity, bandwidth, or other
redundancy to limit the effects of information flooding types of Denial of
Service (DoS) attacks."
  desc  "Utilize network safeguards to limit the ability of Elasticsearch to
launch DOS attacks. Dynamic scripting is disabled by default, limiting the
ability of an Elasticsearch process to affect resources outside of the
Elasticsearch cluster. The snapshot and recovery function of elasticsearch,
which can target a URL, should be granted only to the appropriate roles using
RBAC privileges (cluster:admin/snapshot/*) and is required to be given a
whitelist of targets (repositories.url.allowed_urls)."
  impact 0.5
  tag "nist": ["SC-5 (2)", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-34334r1_rule"
  tag "stig_id": "SRG-APP-000247"
  tag "cci": "CCI-001095"
  tag "check": "Utilize network safeguards to limit the ability of
Elasticsearch to launch DOS attacks. Painless, a sandboxed scripting is the
only script enabled by default, limiting the ability of an Elasticsearch
process to affect resources outside of the Elasticsearch cluster.

As the application administrator (usually elasticsearch, check the
script.engine setting do not enable other languages by running the following:


$ cat config/elasticsearch.yml | grep script.engine

This setting should not be present, return true for painless, or false for
javascript, groovy, python, and java.

As the application administrator (usually elasticsearch, check the plugins
folder does not include other scripting languages by running the following:

$ ls <ES_HOME>/plugins/lang-javascript
$ ls <ES_HOME>/plugins/lang-python

If any of these return a response other than 'No such file or directory',
this is a finding.
"
  tag "fix": "Limit the effects of DoS by setting up network safeguards.

See the official documentation for the safeguading of scripts:
https://www.elastic.co/guide/en/elasticsearch/reference/current/modules-scripting-security.html


As the application administrator (usually elasticsearch, check the plugins
folder does not include other scripting languages by running the following:

$ sudo bin/elasticsearch-plugin remove lang-javascript
$ sudo bin/elasticsearch-plugin remove lang-python
"
end
