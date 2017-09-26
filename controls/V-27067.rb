control "V-27067" do
  title "Applications must support the requirement to activate an alarm and/or
automatically shut down the information system if an application component
failure is detected.  This can include conducting a graceful application
shutdown to avoid losing information."
  desc  "Configure automated alarms to proactively notify when the security or
stability of the system is threatened"
  impact 0.5
  tag "nist": ["SI-13 (4) (b)", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-34362r1_rule"
  tag "stig_id": "SRG-APP-000268"
  tag "cci": "CCI-001328"
  tag "check": "Elasticsearch is designed to be deployed across a number of
nodes, across physical machines and racks.  A single elasticsearch node, is
designed to fail, and the cluster is built to handle this failure, replicating
any lost data, updating its system state, and continue processing.

As an elasticsearch administrator test; verify runtime environment within
_culster stats have at least 3 master nodes, 2 data, and replicatoin minimum of
at least 1.

$curl -H 'Content-Type: application/json' -u <TEST_USER>:<TEST_CREDENTIALS>
-XGET 'http://<elasticsearch>:9200/_cluster/stats'
- indices.shards.index.replication.min:1
- nodes.count.total:3
- nodes.count.data:2

If these cluster stats do not meet the mnimum, this is a finding. "
  tag "fix": "Elastic components should be installed on multiple physical and
rack seperated machines to ensure application built to handle component
failures.

See the official documentation for RPM installation at:
https://www.elastic.co/guide/en/elasticsearch/reference/current/rpm.html"
end
