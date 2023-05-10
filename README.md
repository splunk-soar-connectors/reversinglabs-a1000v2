[comment]: # "Auto-generated SOAR connector documentation"
# Reversinglabs A1000 v2

Publisher: ReversingLabs  
Connector Version: 1.0.1  
Product Vendor: ReversingLabs  
Product Name: A1000  
Product Version Supported (regex): ".\*"  
Minimum Product Version: 5.5.0  

App integrates with ReversingLabs A1000 Malware Analysis Appliance APIs

[comment]: # " File: README.md"
[comment]: # "  Copyright (c) ReversingLabs, 2023"
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""



### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a A1000 asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**url** |  required  | string | A1000 url
**token** |  required  | password | A1000 token

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[detonate file](#action-detonate-file) - Upload file to A1000  
[submit url](#action-submit-url) - Detonate file from url  
[check submitted url status](#action-check-submitted-url-status) - Check submitted url status  
[create pdf report](#action-create-pdf-report) - Create pdf report  
[check pdf report creation](#action-check-pdf-report-creation) - Check pdf report creation  
[download pdf report](#action-download-pdf-report) - Download pdf report  
[get titaniumcore report](#action-get-titaniumcore-report) - Get TitaniumCore report  
[url reputation](#action-url-reputation) - Queries URL info  
[domain reputation](#action-domain-reputation) - Queries domain info  
[ip reputation](#action-ip-reputation) - Queries IP info  
[network ip to domain](#action-network-ip-to-domain) - Get a list of IP-to-domain mappings  
[network urls from ip](#action-network-urls-from-ip) - Get a list of URLs hosted on the requested IP address  
[network files from ip](#action-network-files-from-ip) - Get a a list of hashes and classifications for files found on the requested IP address  
[advanced search](#action-advanced-search) - Search for samples using multi-part search criteria  
[create dynamic analysis report](#action-create-dynamic-analysis-report) - Initiate the creation of dynamic analysis PDF report  
[check dynamic analysis report status](#action-check-dynamic-analysis-report-status) - Get status of the report previously requested  
[download dynamic analysis report](#action-download-dynamic-analysis-report) - Download previously requested dynamic analysis report in pdf  
[get summary report](#action-get-summary-report) - Get a summary report for hash  
[get detailed report](#action-get-detailed-report) - Get detailed analysis report  
[get classification](#action-get-classification) - Get classification for a sample  

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

Validate the asset configuration for connectivity using supplied configuration.

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'detonate file'
Upload file to A1000

Type: **investigate**  
Read only: **True**

Upload file to A1000.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**vault_id** |  required  | Vault ID of file to detonate | string |  `apk`  `doc`  `flash`  `jar`  `pdf`  `pe file`  `ppt`  `xls` 
**file_name** |  optional  | Filename to use | string |  `file name` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |  
action_result.parameter.file_name | string |  `file name`  |  
action_result.parameter.vault_id | string |  `pe file`  `pdf`  `flash`  `apk`  `jar`  `doc`  `xls`  `ppt`  |  
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'submit url'
Detonate file from url

Type: **generic**  
Read only: **False**

Detonate file from url.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**file_url** |  required  | URL from which the appliance should download the data | string | 
**crawler** |  optional  | Crawler method (local or cloud) | string | 
**archive_password** |  optional  | Password, if file is a password-protected archive | string | 
**rl_cloud_sandbox_platform** |  optional  | Cloud Sandbox platform (windows7 or windows10) | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |  
action_result.parameter.archive_password | string |  |  
action_result.parameter.crawler | string |  |  
action_result.parameter.file_url | string |  |  
action_result.parameter.rl_cloud_sandbox_platform | string |  |  
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'check submitted url status'
Check submitted url status

Type: **generic**  
Read only: **False**

Check submitted url status. Returns report if ready.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**task_id** |  required  | Id of the task | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |  
action_result.parameter.task_id | string |  |  
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'create pdf report'
Create pdf report

Type: **generic**  
Read only: **False**

Initiate pdf report creation.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** |  required  | Hash | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |  
action_result.parameter.hash | string |  |  
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'check pdf report creation'
Check pdf report creation

Type: **generic**  
Read only: **False**

Check pdf report creation status.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** |  required  | Hash | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |  
action_result.parameter.hash | string |  |  
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'download pdf report'
Download pdf report

Type: **generic**  
Read only: **False**

Download pdf report.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** |  required  | Hash | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |  
action_result.parameter.hash | string |  |  
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'get titaniumcore report'
Get TitaniumCore report

Type: **generic**  
Read only: **False**

Accepts a single hash string and gets the full TitaniumCore static analysis report for the requested sample.The requested sample must be present on the appliance. If the optional fields parameter is not provided in the request, all available parts of the static analysis report are returned in the response.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** |  required  | Hash | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |  
action_result.parameter.hash | string |  |  
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'url reputation'
Queries URL info

Type: **investigate**  
Read only: **True**

Queries URL info.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** |  required  | URL to query | string |  `url` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |  
action_result.parameter.url | string |  `url`  |  
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'domain reputation'
Queries domain info

Type: **investigate**  
Read only: **True**

Queries domain info.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain to query | string |  `domain`  `url` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |  
action_result.parameter.domain | string |  `domain`  `url`  |  
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'ip reputation'
Queries IP info

Type: **investigate**  
Read only: **True**

Queries IP info.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP to query | string |  `ip` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |  
action_result.parameter.ip | string |  `ip`  |  
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'network ip to domain'
Get a list of IP-to-domain mappings

Type: **generic**  
Read only: **False**

Accepts an IP address string and returns a list of IP-to-domain mappings.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP address | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |  
action_result.parameter.ip | string |  |  
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'network urls from ip'
Get a list of URLs hosted on the requested IP address

Type: **generic**  
Read only: **False**

Accepts an IP address string and returns a list of URLs hosted on the requested IP address.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP address | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |  
action_result.parameter.ip | string |  |  
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'network files from ip'
Get a a list of hashes and classifications for files found on the requested IP address

Type: **generic**  
Read only: **False**

Accepts an IP address string and returns a list of hashes and classifications for files found on the requested IP address.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP address | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |  
action_result.parameter.ip | string |  |  
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'advanced search'
Search for samples using multi-part search criteria

Type: **generic**  
Read only: **False**

Search for samples available on the local A1000 instance and TitaniumCloud using the Advanced Search capabilities.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**query** |  required  | Advanced Search query | string | 
**limit** |  optional  | Maximum number of results | numeric | 
**only_cloud_results** |  optional  | Show only Titanimcloud results | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |  
action_result.parameter.limit | numeric |  |  
action_result.parameter.only_cloud_results | boolean |  |  
action_result.parameter.query | string |  |  
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'create dynamic analysis report'
Initiate the creation of dynamic analysis PDF report

Type: **generic**  
Read only: **False**

Accepts a single hash string and and a report format and initiates the creation of PDF or HTML reports for samples that have gone through dynamic analysis in the ReversingLabs Cloud Sandbox.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** |  required  | Hash | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |  
action_result.parameter.hash | string |  |  
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'check dynamic analysis report status'
Get status of the report previously requested

Type: **generic**  
Read only: **False**

Accepts a single hash string and report format parameters that should correspond to the parameters used in the request with create_dynamic_analysis_report method. The response includes an informative message about the status of the report previously requested.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** |  required  | Hash | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |  
action_result.parameter.hash | string |  |  
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'download dynamic analysis report'
Download previously requested dynamic analysis report in pdf

Type: **generic**  
Read only: **False**

Accepts a single hash string and report format parameters that should correspond to the parameters used in the request with create_dynamic_analysis_report method.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** |  required  | Hash | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |  
action_result.parameter.hash | string |  |  
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'get summary report'
Get a summary report for hash

Type: **generic**  
Read only: **False**

Get a summary report for hash.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** |  required  | Hash | string | 
**retry** |  optional  | If set to False there will only be one try at obtaining the analysis report | boolean | 
**fields** |  optional  | List of A1000 report 'fields' to query | string | 
**include_network_threat_intelligence** |  optional  | Include network threat intelligence in the summary report | boolean | 
**skip_reanalysis** |  optional  | Skip sample reanalysis when fetching the summary report | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |  
action_result.parameter.fields | string |  |  
action_result.parameter.hash | string |  |  
action_result.parameter.include_network_threat_intelligence | boolean |  |  
action_result.parameter.retry | boolean |  |  
action_result.parameter.skip_reanalysis | boolean |  |  
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'get detailed report'
Get detailed analysis report

Type: **generic**  
Read only: **False**

Get detailed analysis report for sample.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** |  required  | Hash | string | 
**retry** |  optional  | If set to False there will only be one try at obtaining the analysis report | boolean | 
**fields** |  optional  | List of A1000 report 'fields' to query | string | 
**skip_reanalysis** |  optional  | Skip sample reanalysis when fetching the summary report | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |  
action_result.parameter.fields | string |  |  
action_result.parameter.hash | string |  |  
action_result.parameter.retry | boolean |  |  
action_result.parameter.skip_reanalysis | boolean |  |  
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'get classification'
Get classification for a sample

Type: **generic**  
Read only: **False**

Get classification for one sample. The default value of local_only is False, which, if not changed, will send a request to TitaniumCloud to get the sample. The av_scanners parameter decides if the AV scanner results will be included in the classification report.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** |  required  | Hash | string | 
**local_only** |  optional  | Return only local samples without querying TitaniumCloud | boolean | 
**av_scanners** |  optional  | Return AV scanner results | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |  
action_result.parameter.av_scanners | boolean |  |  
action_result.parameter.hash | string |  |  
action_result.parameter.local_only | boolean |  |  
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |  