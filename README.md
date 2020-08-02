# WIP: ElasticSearch STIG Benchmark (Draft) - InSpec Profile

## Description

This [InSpec](https://github.com/chef/inspec) compliance profile implement the [ElasticSearch Security Technical Implementation Guide (STIG) - (Draft)](https://github.com/elastic/elasticsearch-inspec) in an automated way to provide security best-practice tests around ElasticSearch with X-pack server and system settings in a production environment.

InSpec is an open-source run-time framework and rule language used to specify compliance, security, and policy requirements for testing any node in your infrastructure.

## Requirements

- At least [InSpec](http://inspec.io/) version 1.43.5 or higher
- ElasticSearch v. 5.x or higher
- X-pack v. 5.x or higher

### Tested Platforms

This profile is being developed and tested along side a `hardening` recipe. The [elasticsearch-inspec-hardening](https://github.com/mitre/elasticsearch-hardening) will help you configure and deploy your ElasticSearch with X- pack instance to meet the requirements of the security baseline.

- CentOS 7
- RHEL 7

It should work on other platforms, however, we have not yet formally tested it (PR's welcome) .

## Attributes

We use a yml attribute file to steer the configuration, the following options are available:

- description: 'IP address of the elasticsearch instance',<br>
  `elastic_ip: '0.0.0.0'`

- description: 'Port address of the elasticsearch instance',<br>
  `elastic_port: '9200'`

- description: 'Path to elasticsearch home directory'<br>
  `es_home: '/etc/elasticsearch'`

- description: 'Path to elasticsearch.yaml',<br>
  `elasticsearch_conf: '/etc/elasticsearch/elasticsearch.yml'`

- description: 'List of managed access points',<br>
  `managed_access_points: ['10.0.2.15']`

- description: 'Elasticsearch admin',<br>
  `es_admin: 'elastic'`

- description: 'Elasticsearch admin password',<br>
  `es_pass: 'changeme'`

- description: 'List of superusers',<br>
  `es_superusers: ['elastic']`

- description: 'List of events to be logged',<br>
  `es_included_logevents: ['access_denied', 'anonymous_access_denied', 'authentication_failed', 'connection_denied', 'tampered_request', 'run_as_denied', 'run_as_granted']`

- description: 'List of events to be excluded',<br>
  `es_excluded_logevents: ['access_granted']`

- description: 'Elasticsearch owner',<br>
  `es_owner: 'elasticsearch'`

- description: 'Elasticsearch group',<br>
  `es_group: 'elasticsearch'`

- description: 'Path to rsyslog.conf',<br>
  `rsyslog_conf: '/etc/rsyslog.conf'`

- description: 'URI to the log aggregation system',<br>
  `log_aggregation_system: 'logagg.site.mil'`

- description: 'List of NSA-approved or FIPS validated cipher suites',<br>
  `approved_cipher_suites: ['TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256', 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256','TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA', 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA','TLS_RSA_WITH_AES_128_CBC_SHA256','TLS_RSA_WITH_AES_128_CBC_SHA']`

## Usage

InSpec makes it easy to run your tests wherever you need. More options listed here: [InSpec cli](http://inspec.io/docs/reference/cli/)

```
# run profile locally
$ git clone https://github.com/elastic/elasticsearch-inspec
$ inspec exec elasticsearch-inspec

# run profile locally and directly from Github
$ inspec exec https://github.com/elastic/elasticsearch-inspec

# run profile on remote host via SSH
inspec exec elasticsearch-inspec -t ssh://user@hostname -i /path/to/key

# run profile on remote host via SSH with sudo
inspec exec elasticsearch-inspec -t ssh://user@hostname -i /path/to/key --sudo

# run profile on remote host via SSH with sudo and define attribute value
inspec exec elasticsearch-inspec --attrs attributes.yml
```

### Run individual controls

In order to verify individual controls, just provide the control ids to InSpec:

```
inspec exec elasticsearch-inspec --controls 'V-26699 V-27130'
```

## Contributors + Kudos

- Rony Xavier [rx294](https://github.com/rx294)
- Aaron Lippold [aaronlippold](https://github.com/aaronlippold)
- Matt Isett [matt-isett](https://github.com/matt-isett)

## License and Author

- Author:: Rony Xaiver [rx294@gmail.com](mailto:rx294@gmail.com)
- Author:: Aaron Lippold [lippold@gmail.com](mailto:lippold@gmail.com)
- Author:: Matt Isett [matt.isett@elastic.co](mailto:matt.isett@elastic.co)

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

```
http://www.apache.org/licenses/LICENSE-2.0
```

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

### NOTICE  

© 2020 The MITRE Corporation.  

Approved for Public Release; Distribution Unlimited. Case Number 18-3678.  

### NOTICE
MITRE hereby grants express written permission to use, reproduce, distribute, modify, and otherwise leverage this software to the extent permitted by the licensed terms provided in the LICENSE.md file included with this project.

### NOTICE  

This software was produced for the U. S. Government under Contract Number HHSM-500-2012-00008I, and is subject to Federal Acquisition Regulation Clause 52.227-14, Rights in Data-General.  

No other use other than that granted to the U. S. Government, or to those acting on behalf of the U. S. Government under that Clause is authorized without the express written permission of The MITRE Corporation. 

For further information, please contact The MITRE Corporation, Contracts Management Office, 7515 Colshire Drive, McLean, VA  22102-7539, (703) 983-6000.  

### NOTICE  

DISA STIGs are published by DISA IASE, see: https://iase.disa.mil/Pages/privacy_policy.aspx  
