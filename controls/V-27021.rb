control "V-27021" do
  title "Applications must be built to fail to a known safe state for defined
types of failures."
  desc  "Elastic components should be installed on multiple physical and rack
separated machines to ensure application built to handle failures."
  impact 0.5
  tag "nist": ["SC-24", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-34315r1_rule"
  tag "gtitle": "SRG-APP-000225"
  tag "cci": "CCI-001190"
  tag "check": "Elasticsearch is designed to be deployed across a number of
nodes, across physical machines and racks.  A single elasticsearch node, is
designed to fail, and the cluster is built to handle this failure, replicating
any lost data, updating its system state, and continue processing.

As an elasticsearch administrator test; verify runtime environment within
_culster stats have at least 3 master nodes, 2 data, and replication minimum of
at least 1.

$curl -H 'Content-Type: application/json' -u <TEST_USER>:<TEST_CREDENTIALS>
-XGET 'http://<elasticsearch>:9200/_cluster/stats'
- indices.shards.index.replication.min:1
- nodes.count.total:3
- nodes.count.data:2

If these cluster stats do not meet the minimum, this is a finding. "
  tag "fix": "Elastic components should be installed on multiple physical and
rack separated machines to ensure application built to handle failures.

See the official documentation for RPM installation at:
https://www.elastic.co/guide/en/elasticsearch/reference/current/rpm.html"
end
