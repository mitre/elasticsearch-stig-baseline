control "V-26966" do
  title "Backup / Disaster Recovery oriented applications must be capable of
backing up user-level information per a defined frequency."
  desc  "As appropriate, backup data within Elasticsearch. Plan and test
restoration processes for this information. Utilize snapshot and restore
features of elasticsearch."
  impact 0.5
  tag "nist": ["CP-9 (a)", "Rev_4"]
  tag "severity": "medium"
  tag "rid": "SV-34251r1_rule"
  tag "stig_id": "SRG-APP-000145"
  tag "cci": "CCI-000535"
  tag "check": "User-level information is maintained within the standard
backup/restore functionality within the application. A cronjob should be
created to run according to <ORGANIZATIONAL_DEFINED> frequency.

To verify user-level information is stored correctly; as the security
administrator, run the following CURL command:

$ curl -XGET  -H 'Content-Type: application/json' -u <TEST_USER> -p
<TEST_CREDENTIALS> https://<elasticsearch>:9200/_xpack/security/role
$ curl -XGET  -H 'Content-Type: application/json' -u <TEST_USER> -p
<TEST_CREDENTIALS> https://<elasticsearch>:9200/_xpack/security/role_mapping


Review the results, if any results are incorrect or none are defined, this is a
finding.

To verify that a repository; <REPOSITORY_NAME>; is available; as the security
administrator, run the following CURL command:

$ curl -XPOST -H 'Content-Type: application/json' -u
<TEST_USER>:<TEST_CREDENTIALS>
https://<elasticsearch>:9200/_snapshot/<REPOSITORY_NAME>/_verify?pretty=true


Review the results, if error message is returned, this is a finding.

If no script/tool is scheduled to perform a snaphost at the
<ORGANIZATIONAL_DEFINED> frequency, this is a finding.
     "
  tag "fix": "Setup roles, role mapping, repository, and cron job to faciliate
Backup/ Disaster Recovery including user-level information.

See the official documentation for the guide on roles:
https://www.elastic.co/guide/en/x-pack/current/authorization.html

See the official documentation for the guide on role mapping:
https://www.elastic.co/guide/en/elasticsearch/reference/current/security-api-role-mapping.html


See the official documentation for the guide on repository:
https://www.elastic.co/guide/en/elasticsearch/reference/current/modules-snapshots.html


Elasticsearch does not schedule when to perform the snapshot, however, it is
possible to schedule snaphosts with a script.

##### Example Snapshot Script

#!/bin/bash
SNAPSHOT=`date +%Y%m%d-%H%M%S`
REPOSITORY_NAME=<REPOSITORY_NAME>
curl -XPUT
'<elasticsearch>:9200/_snapshot/REPOSITORY_NAME/$SNAPSHOT?wait_for_completion=true'


##### Example Snapshot Script

Schedule this script in cron to run at <ORGANIZATIONAL_DEFINED> frequency.



"
end
