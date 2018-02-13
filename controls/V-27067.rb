ELASTIC_IP= attribute(
  'elastic_ip',
  description: 'IP address of the elasticsearch instance',
  default: '0.0.0.0'
)

ELASTIC_PORT= attribute(
  'elastic_port',
  description: 'Port address of the elasticsearch instance',
  default: '9200'
)

ES_ADMIN = attribute(
  'es_admin',
  description: 'Elasticsearch admin',
  default: 'elastic'
)

ES_PASS = attribute(
  'es_pass',
  description: 'Elasticsearch admin password',
  default: 'changeme'
)

ES_SERVICE_NAME= attribute(
  'es_service_name',
  description: 'Name of Elasticsearch service',
  default: 'elasticsearch'
)

only_if do
  service(ES_SERVICE_NAME).installed?
end

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
  tag "gtitle": "SRG-APP-000268"
  tag "cci": "CCI-001328"
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
rack separated machines to ensure application built to handle component
failures.

See the official documentation for RPM installation at:
https://www.elastic.co/guide/en/elasticsearch/reference/current/rpm.html"

  begin
    cmd = "curl -XGET  -H 'Content-Type: application/json' https://#{ELASTIC_IP}:#{ELASTIC_PORT}/_cluster/stats -k -u #{ES_ADMIN}:#{ES_PASS}"
    cluster_stats = json(command:cmd).params

    describe cluster_stats['nodes']['count'] do
      its(['total']) { should cmp >= 3 }
      its(['data']) { should cmp >= 2 }
    end

    describe cluster_stats['indices']['shards']['index']['replication'] do
      its(['min']) { should cmp >= 1 }
    end

  rescue Exception => msg
    describe "Exception: #{msg}" do
      it { should be_nil}
    end
  end
end
