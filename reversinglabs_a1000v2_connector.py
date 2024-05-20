# File: reversinglabs_a1000v2_connector.py
#
# Copyright (c) ReversingLabs, 2023
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
#
from __future__ import print_function, unicode_literals

import json
import os

# Phantom App imports
import phantom.app as phantom
from phantom import vault
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector
from phantom.vault import Vault
from ReversingLabs.SDK.a1000 import A1000

# Our helper lib reversinglabs-sdk-py3 internally utilizes pypi requests (with named parameters) which is shadowed by Phantom
# requests (which has renamed parameters (url>>uri), hence this workarounds
old_get = phantom.requests.get


def new_get(url, **kwargs):
    return old_get(url, **kwargs)


phantom.requests.get = new_get

old_post = phantom.requests.post


def new_post(url, **kwargs):
    return old_post(url, **kwargs)


phantom.requests.post = new_post

old_delete = phantom.requests.delete


def new_delete(url, **kwargs):
    return old_delete(url, **kwargs)


phantom.requests.delete = new_delete


class ReversinglabsA1000V2Connector(BaseConnector):
    post_url = "post_url"
    USER_AGENT = "ReversingLabs Splunk SOAR A1000 v1.0.0"
    TITANIUM_CORE_FIELDS = "sha1, sha256, sha512, md5, imphash, info, application, protection, security, behaviour," \
        " certificate, document, mobile, media, web, email, strings, interesting_strings," \
        " classification, indicators, tags, attack, story"

    # The actions supported by this connector
    ACTION_ID_TEST_CONNECTIVITY = "test_connectivity"
    ACTION_ID_DETONATE_FILE = "detonate_file"
    ACTION_ID_DETONATE_FILE_FROM_URL = "detonate_file_from_url"
    ACTION_ID_CHECK_SUBMITTED_URL_STATUS = "check_submitted_url_status"
    ACTION_ID_CREATE_PDF_REPORT = "create_pdf_report"
    ACTION_ID_CHECK_PDF_REPORT_CREATION = "check_pdf_report_creation"
    ACTION_ID_DOWNLOAD_PDF_REPORT = "download_pdf_report"
    ACTION_ID_GET_TITANIUMCORE_REPORT = "get_titaniumcore_report"
    ACTION_ID_URL_REPUTATION = "url_reputation"
    ACTION_ID_DOMAIN_REPUTATION = "domain_reputation"
    ACTION_ID_IP_REPUTATION = "ip_reputation"
    ACTION_ID_NETWORK_IP_TO_DOMAIN = "network_ip_to_domain"
    ACTION_ID_NETWORK_URLS_FROM_IP = "network_urls_from_ip"
    ACTION_ID_NETWORK_FILES_FROM_IP = "network_files_from_ip"
    ACTION_ID_ADVANCED_SEARCH = "advanced_search"
    ACTION_ID_CREATE_DYNAMIC_ANALYSIS_REPORT = "create_dynamic_analysis_report"
    ACTION_ID_CHeck_DYNAMIC_ANALYSIS_REPORT_STATUS = "check_dynamic_analysis_report_status"
    ACTION_ID_DOWNLOAD_DYNAMIC_ANALYSIS_REPORT = "download_dynamic_analysis_report"
    ACTION_ID_GET_SUMMARY_REPORT = "get_summary_report"
    ACTION_ID_GET_DETAILED_REPORT = "get_detailed_report"
    ACTION_ID_GET_CLASSIFICATION = "get_classification"
    ACTION_ID_RETRIEVE_USER_TAGS = "retrieve_user_tags"
    ACTION_ID_CREATE_USER_TAGS = "create_user_tags"
    ACTION_ID_DELETE_USER_TAGS = "delete_user_tags"
    ACTION_ID_SET_SAMPLE_CLASSIFICATION = "set_sample_classification"
    ACTION_ID_DELETE_SAMPLE_CLASSIFICATION = "delete_sample_classification"
    ACTION_ID_YARA_GET_RULES = "yara_get_rules"
    ACTION_ID_YARA_GET_RULE_CONTENT = "yara_get_rule_content"
    ACTION_ID_YARA_MATCHES = "yara_matches"
    ACTION_ID_YARA_CREATE_RULE = "yara_create_rule"
    ACTION_ID_YARA_DELETE_RULE = "yara_delete_rule"
    ACTION_ID_YARA_TOGGLE_RULE = "yara_toggle_rule"
    ACTION_ID_YARA_GET_SYNC_TIME = "yara_get_sync_time"
    ACTION_ID_YARA_SET_SYNC_TIME = "yara_set_sync_time"
    ACTION_ID_YARA_TOGGLE_RETRO_SCAN_LOCAL = "yara_toggle_retro_scan_local"
    ACTION_ID_YARA_MANAGE_RETRO_SCAN_CLOUD = "yara_manage_retro_scan_cloud"
    ACTION_ID_YARA_CHECK_RETRO_SCAN_LOCAL = "yara_check_retro_scan_local"
    ACTION_ID_YARA_STATUS_RETRO_SCAN_LOCAL = "yara_status_retro_scan_local"
    ACTION_ID_YARA_STATUS_RETRO_SCAN_CLOUD = "yara_status_retro_scan_cloud"
    ACTION_ID_LIST_CONTAINERS_FOR_HASH = "list_containers_for_hash"
    ACTION_ID_DELETE_SAMPLE = "delete_sample"
    ACTION_ID_DOWNLOAD_EXTRACTED_FILES = "download_extracted_files"
    ACTION_ID_REANALYZE_SAMPLES = "reanalyze_samples"

    def __init__(self):
        # Call the BaseConnectors init first
        super(ReversinglabsA1000V2Connector, self).__init__()

        self.ACTIONS = {
            self.ACTION_ID_TEST_CONNECTIVITY: self._handle_test_connectivity,
            self.ACTION_ID_DETONATE_FILE: self._handle_detonate_file,
            self.ACTION_ID_DETONATE_FILE_FROM_URL: self._handle_detonate_file_from_url,
            self.ACTION_ID_CHECK_SUBMITTED_URL_STATUS: self._handle_check_submitted_url_status,
            self.ACTION_ID_CREATE_PDF_REPORT: self._handle_create_pdf_report,
            self.ACTION_ID_CHECK_PDF_REPORT_CREATION: self._handle_check_pdf_report_creation,
            self.ACTION_ID_DOWNLOAD_PDF_REPORT: self._handle_download_pdf_report,
            self.ACTION_ID_GET_TITANIUMCORE_REPORT: self._handle_get_titaniumcore_report,
            self.ACTION_ID_URL_REPUTATION: self._handle_url_reputation,
            self.ACTION_ID_DOMAIN_REPUTATION: self._handle_domain_reputation,
            self.ACTION_ID_IP_REPUTATION: self._handle_ip_reputation,
            self.ACTION_ID_NETWORK_IP_TO_DOMAIN: self._handle_network_ip_to_domain,
            self.ACTION_ID_NETWORK_URLS_FROM_IP: self._handle_network_urls_from_ip,
            self.ACTION_ID_NETWORK_FILES_FROM_IP: self._handle_network_files_from_ip,
            self.ACTION_ID_ADVANCED_SEARCH: self._handle_advanced_search,
            self.ACTION_ID_CREATE_DYNAMIC_ANALYSIS_REPORT: self._handle_create_dynamic_analysis_report,
            self.ACTION_ID_CHeck_DYNAMIC_ANALYSIS_REPORT_STATUS: self._handle_check_dynamic_analysis_report_status,
            self.ACTION_ID_DOWNLOAD_DYNAMIC_ANALYSIS_REPORT: self._handle_download_dynamic_analysis_report,
            self.ACTION_ID_GET_SUMMARY_REPORT: self._handle_get_summary_report,
            self.ACTION_ID_GET_DETAILED_REPORT: self._handle_get_detailed_report,
            self.ACTION_ID_GET_CLASSIFICATION: self._handle_get_classification,

            self.ACTION_ID_RETRIEVE_USER_TAGS: self._handle_retrieve_user_tags,
            self.ACTION_ID_CREATE_USER_TAGS: self._handle_create_user_tags,
            self.ACTION_ID_DELETE_USER_TAGS: self._handle_delete_user_tags,
            self.ACTION_ID_SET_SAMPLE_CLASSIFICATION: self._handle_set_sample_classification,
            self.ACTION_ID_DELETE_SAMPLE_CLASSIFICATION: self._handle_delete_sample_classification,
            self.ACTION_ID_YARA_GET_RULES: self._handle_yara_get_rules,
            self.ACTION_ID_YARA_GET_RULE_CONTENT: self._handle_get_rule_content,
            self.ACTION_ID_YARA_MATCHES: self._handle_yara_matches,
            self.ACTION_ID_YARA_CREATE_RULE: self._handle_yara_create_rule,
            self.ACTION_ID_YARA_DELETE_RULE: self._handle_yara_delete_rule,
            self.ACTION_ID_YARA_TOGGLE_RULE: self._handle_yara_toggle_rule,
            self.ACTION_ID_YARA_GET_SYNC_TIME: self._handle_yara_get_sync_time,
            self.ACTION_ID_YARA_SET_SYNC_TIME: self._handle_yara_set_sync_time,
            self.ACTION_ID_YARA_TOGGLE_RETRO_SCAN_LOCAL: self._handle_yara_toggle_retro_scan_local,
            self.ACTION_ID_YARA_MANAGE_RETRO_SCAN_CLOUD: self._handle_yara_manage_retro_scan_cloud,
            self.ACTION_ID_YARA_STATUS_RETRO_SCAN_LOCAL: self._handle_yara_status_retro_scan_local,
            self.ACTION_ID_YARA_STATUS_RETRO_SCAN_CLOUD: self._handle_yara_status_retro_scan_cloud,
            self.ACTION_ID_LIST_CONTAINERS_FOR_HASH: self._handle_list_containers_for_hash,
            self.ACTION_ID_DELETE_SAMPLE: self._handle_delete_sample,
            self.ACTION_ID_DOWNLOAD_EXTRACTED_FILES: self._handle_download_extracted_files,
            self.ACTION_ID_REANALYZE_SAMPLES: self._handle_reanalyze_samples
        }

        self._state = None

    def initialize(self):
        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()
        self.a1000_url = config["url"]
        self.a1000_token = config["token"]

        self.a1000 = A1000(
            host=self.a1000_url,
            token=self.a1000_token,
            verify=False,
            user_agent=self.USER_AGENT,
        )

        return phantom.APP_SUCCESS

    def finalize(self):
        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS

    def handle_action(self, param):
        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()
        action = self.ACTIONS.get(action_id)
        if not action:
            return

        action_result = self.add_action_result(ActionResult(dict(param)))

        try:
            action(action_result, param)
        except Exception as err:
            return action_result.set_status(phantom.APP_ERROR, str(err))

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_detonate_file(self, action_result, param):
        self.debug_print("Action handler", self.get_action_identifier())

        file_vault_id = param["vault_id"]
        success, msg, files_array = vault.vault_info(container_id=self.get_container_id())
        if not success:
            raise Exception('Unable to get Vault item details. Error details: {0}'.format(msg))

        file = next(filter(lambda x: x["vault_id"] == file_vault_id, files_array), None)
        if not file:
            raise Exception('Unable to get Vault item details. Error details: {0}'.format(msg))

        self.a1000.upload_sample_from_path(file["path"])

        self.debug_print("Executed", self.get_action_identifier())

    def _handle_detonate_file_from_url(self, action_result, param):
        self.debug_print("Action handler", self.get_action_identifier())

        response = self.a1000.upload_sample_from_url(
            file_url=param.get("file_url")
        )
        self.debug_print("Executed", self.get_action_identifier())

        action_result.add_data(response.json())

    def _handle_check_submitted_url_status(self, action_result, param):
        self.debug_print("Action handler", self.get_action_identifier())

        response = self.a1000.check_submitted_url_status(
            task_id=param.get("task_id")
        )

        self.debug_print("Executed", self.get_action_identifier())

        action_result.add_data(response.json())

    def _handle_create_pdf_report(self, action_result, param):
        self.debug_print("Action handler", self.get_action_identifier())

        response = self.a1000.create_pdf_report(sample_hash=param.get('hash'))

        self.debug_print("Executed", self.get_action_identifier())

        action_result.add_data(response.json())

    def _handle_check_pdf_report_creation(self, action_result, param):
        self.debug_print("Action handler", self.get_action_identifier())

        response = self.a1000.check_pdf_report_creation(sample_hash=param.get('hash'))

        self.debug_print("Executed", self.get_action_identifier())

        action_result.add_data(response.json())

    def _handle_download_pdf_report(self, action_result, param):
        self.debug_print("Action handler", self.get_action_identifier())

        response = self.a1000.download_pdf_report(sample_hash=param.get('hash'))

        self.debug_print("Executed", self.get_action_identifier())

        file_path = os.path.join(Vault.get_vault_tmp_dir(), param.get("hash"))
        with open(file_path, "wb") as file_obj:
            file_obj.write(response.content)

        success, msg, vault_id = vault.vault_add(file_location=file_path,
                                                 container=self.get_container_id(),
                                                 file_name="{0}.pdf".format(param.get("hash")))
        if not success:
            raise Exception('Unable to store file in Vault. Error details: {0}'.format(msg))

    def _handle_url_reputation(self, action_result, param):
        self.debug_print("Action handler", self.get_action_identifier())

        response = self.a1000.network_url_report(requested_url=param.get('url'))

        self.debug_print("Executed", self.get_action_identifier())

        action_result.add_data(response.json())

    def _handle_domain_reputation(self, action_result, param):
        self.debug_print("Action handler", self.get_action_identifier())

        response = self.a1000.network_domain_report(domain=param.get('domain'))

        self.debug_print("Executed", self.get_action_identifier())

        action_result.add_data(response.json())

    def _handle_ip_reputation(self, action_result, param):
        self.debug_print("Action handler", self.get_action_identifier())

        response = self.a1000.network_ip_addr_report(ip_addr=param.get('ip'))

        self.debug_print("Executed", self.get_action_identifier())

        action_result.add_data(response.json())

    def _handle_network_ip_to_domain(self, action_result, param):
        self.debug_print("Action handler", self.get_action_identifier())

        response = self.a1000.network_ip_to_domain(ip_addr=param.get('ip'))

        self.debug_print("Executed", self.get_action_identifier())

        action_result.add_data(response.json())

    def _handle_network_urls_from_ip(self, action_result, param):
        self.debug_print("Action handler", self.get_action_identifier())

        response = self.a1000.network_urls_from_ip(ip_addr=param.get('ip'))

        self.debug_print("Executed", self.get_action_identifier())

        action_result.add_data(response.json())

    def _handle_network_files_from_ip(self, action_result, param):
        self.debug_print("Action handler", self.get_action_identifier())

        response = self.a1000.network_files_from_ip(ip_addr=param.get('ip'))

        self.debug_print("Executed", self.get_action_identifier())

        action_result.add_data(response.json())

    def _handle_advanced_search(self, action_result, param):
        self.debug_print("Action handler", self.get_action_identifier())

        response = self.a1000.advanced_search_v2_aggregated(query_string=param.get('query'),
                                                            max_results=param.get('limit'),
                                                            ticloud=param.get('only_cloud_results'))

        self.debug_print("Executed", self.get_action_identifier())

        for result in response:
            action_result.add_data(result)

    def _handle_create_dynamic_analysis_report(self, action_result, param):
        self.debug_print("Action handler", self.get_action_identifier())

        response = self.a1000.create_dynamic_analysis_report(
            sample_hash=param.get('hash'),
            report_format='pdf'
        )

        self.debug_print("Executed", self.get_action_identifier())

        action_result.add_data(response.json())

    def _handle_check_dynamic_analysis_report_status(self, action_result, param):
        self.debug_print("Action handler", self.get_action_identifier())

        response = self.a1000.check_dynamic_analysis_report_status(
            sample_hash=param.get('hash'),
            report_format='pdf'
        )

        self.debug_print("Executed", self.get_action_identifier())

        action_result.add_data(response.json())

    def _handle_download_dynamic_analysis_report(self, action_result, param):
        self.debug_print("Action handler", self.get_action_identifier())

        response = self.a1000.download_dynamic_analysis_report(
            sample_hash=param.get('hash'),
            report_format='pdf'
        )

        self.debug_print("Executed", self.get_action_identifier())

        file_path = os.path.join(Vault.get_vault_tmp_dir(), param.get("hash"))
        with open(file_path, "wb") as file_obj:
            file_obj.write(response.content)

        success, msg, vault_id = vault.vault_add(file_location=file_path,
                                                 container=self.get_container_id(),
                                                 file_name="dynamic-{0}.pdf".format(param.get('hash')))
        if not success:
            raise Exception('Unable to store file in Vault. Error details: {0}'.format(msg))

    def _handle_get_summary_report(self, action_result, param):
        self.debug_print("Action handler", self.get_action_identifier())

        fields = None
        if param.get('fields'):
            fields = param.get('fields').split(",")
        response = self.a1000.get_summary_report_v2(
            sample_hashes=param.get('hash'),
            retry=param.get('retry'),
            fields=fields,
            include_networkthreatintelligence=param.get('include_network_threat_intelligence'),
            skip_reanalysis=param.get('skip_reanalysis')
        )

        self.debug_print("Executed", self.get_action_identifier())

        action_result.add_data(response.json())

    def _handle_get_detailed_report(self, action_result, param):
        # TODO: check how parameters are handled
        self.debug_print("Action handler", self.get_action_identifier())

        fields = None
        if param.get('fields'):
            fields = param.get('fields').split(",")
        response = self.a1000.get_detailed_report_v2(
            sample_hashes=param.get('hash'),
            retry=param.get('retry'),
            fields=fields,
            skip_reanalysis=param.get('skip_reanalysis')
        )

        self.debug_print("Executed", self.get_action_identifier())

        action_result.add_data(response.json())

    def _handle_get_classification(self, action_result, param):
        self.debug_print("Action handler", self.get_action_identifier())

        response = self.a1000.get_classification_v3(
            sample_hash=param.get('hash'),
            local_only=param.get('local_only'),
            av_scanners=param.get('av_scanners')
        )

        self.debug_print("Executed", self.get_action_identifier())

        action_result.add_data(response.json())

    def _handle_get_titaniumcore_report(self, action_result, param):
        self.debug_print("Action handler", self.get_action_identifier())

        response = self.a1000.get_titanium_core_report_v2(
            sample_hash=param.get("hash"),
            fields=self.TITANIUM_CORE_FIELDS
        )

        self.debug_print("Executed", self.get_action_identifier())

        action_result.add_data(response.json())

    def _handle_test_connectivity(self, action_result, param):
        self.debug_print("Action handler", self.get_action_identifier())
        self.a1000.test_connection()

        self.save_progress("Test Connectivity Passed")

    def _handle_retrieve_user_tags(self, action_result, param):
        self.debug_print("Action handler", self.get_action_identifier())

        sample_hash = param.get("hash")
        response = self.a1000.get_user_tags(sample_hash=sample_hash)

        self.debug_print("Executed", self.get_action_identifier())

        action_result.add_data({"tags": response.json()})

    def _handle_create_user_tags(self, action_result, param):
        self.debug_print("Action handler", self.get_action_identifier())

        sample_hash = param.get("hash")
        tags = param.get("tags").split(",")
        response = self.a1000.post_user_tags(
            sample_hash=sample_hash,
            tags=tags
        )

        self.debug_print("Executed", self.get_action_identifier())

        action_result.add_data({"tags": response.json()})

    def _handle_delete_user_tags(self, action_result, param):
        self.debug_print("Action handler", self.get_action_identifier())

        sample_hash = param.get("hash")
        tags = param.get("tags").split(",")
        response = self.a1000.delete_user_tags(
            sample_hash=sample_hash,
            tags=tags
        )

        self.debug_print("Executed", self.get_action_identifier())

        action_result.add_data({"tags": response.json()})

    def _handle_set_sample_classification(self, action_result, param):
        self.debug_print("Action handler", self.get_action_identifier())
        system = param.get("system")
        response = self.a1000.set_classification(
            sample_hash=param.get("hash"),
            classification=param.get("classification").split(),
            system=system,
            risk_score=param.get("risk_score"),
            threat_platform=param.get("threat_platform"),
            threat_type=param.get("threat_type"),
            threat_name=param.get("threat_name"),
        )
        self.debug_print("Executed", self.get_action_identifier())

        content = response.json() if system == "local" else None

        action_result.add_data({"source": system, "content": content})

    def _handle_delete_sample_classification(self, action_result, param):
        self.debug_print("Action handler", self.get_action_identifier())
        system = param.get("system")
        response = self.a1000.delete_classification(
            sample_hash=param.get("hash"),
            system=system,
        )
        self.debug_print("Executed", self.get_action_identifier())

        content = response.json() if system == "local" else None

        action_result.add_data({"source": system, "content": content})

    def _handle_yara_get_rules(self, action_result, param):
        self.debug_print("Action handler", self.get_action_identifier())
        response = self.a1000.get_yara_rulesets_on_the_appliance_v2(
            owner_type=param.get("owner"),
            status=param.get("status"),
            source=param.get("source"),
            page=param.get("page"),
            page_size=param.get("page_size")
        )
        self.debug_print("Executed", self.get_action_identifier())
        action_result.add_data(response.json())

    def _handle_get_rule_content(self, action_result, param):
        self.debug_print("Action handler", self.get_action_identifier())
        response = self.a1000.get_yara_ruleset_contents(
            ruleset_name=param.get("name")
        )
        self.debug_print("Executed", self.get_action_identifier())
        action_result.add_data(response.json())

    def _handle_yara_matches(self, action_result, param):
        self.debug_print("Action handler", self.get_action_identifier())
        response = self.a1000.get_yara_ruleset_matches_v2(
            ruleset_name=param.get("name"),
            page=param.get("page"),
            page_size=param.get("page_size")
        )
        self.debug_print("Executed", self.get_action_identifier())
        action_result.add_data(response.json())

    def _handle_yara_create_rule(self, action_result, param):
        self.debug_print("Action handler", self.get_action_identifier())
        response = self.a1000.create_or_update_yara_ruleset(
            name=param.get("name"),
            content=param.get("content"),
            publish=param.get("publish"),
            ticloud=param.get("ticloud")
        )
        self.debug_print("Executed", self.get_action_identifier())
        action_result.add_data(response.json())

    def _handle_yara_delete_rule(self, action_result, param):
        self.debug_print("Action handler", self.get_action_identifier())
        response = self.a1000.delete_yara_ruleset(
            name=param.get("name"),
            publish=param.get("publish"),
        )
        self.debug_print("Executed", self.get_action_identifier())
        action_result.add_data(response.json())

    def _handle_yara_toggle_rule(self, action_result, param):
        self.debug_print("Action handler", self.get_action_identifier())
        response = self.a1000.enable_or_disable_yara_ruleset(
            name=param.get("name"),
            enabled=param.get("enabled"),
            publish=param.get("publish"),
        )
        self.debug_print("Executed", self.get_action_identifier())
        action_result.add_data(response.json())

    def _handle_yara_get_sync_time(self, action_result, param):
        # TODO: check how to handle the 405 error here, should we enrich the action output or just let it fail
        self.debug_print("Action handler", self.get_action_identifier())
        response = self.a1000.get_yara_ruleset_synchronization_time()
        self.debug_print("Executed", self.get_action_identifier())
        action_result.add_data(response.json())

    def _handle_yara_set_sync_time(self, action_result, param):
        self.debug_print("Action handler", self.get_action_identifier())
        response = self.a1000.update_yara_ruleset_synchronization_time(
            sync_time=param.get("time"),
        )
        self.debug_print("Executed", self.get_action_identifier())
        action_result.add_data(response.json())

    def _handle_yara_toggle_retro_scan_local(self, action_result, param):
        self.debug_print("Action handler", self.get_action_identifier())
        response = self.a1000.start_or_stop_yara_local_retro_scan(
            operation=param.get("operation"),
        )
        self.debug_print("Executed", self.get_action_identifier())
        action_result.add_data(response.json())

    def _handle_yara_manage_retro_scan_cloud(self, action_result, param):
        self.debug_print("Action handler", self.get_action_identifier())
        response = self.a1000.start_or_stop_yara_cloud_retro_scan(
            operation=param.get("operation"),
            ruleset_name=param.get("ruleset_name"),
        )
        self.debug_print("Executed", self.get_action_identifier())
        action_result.add_data(response.json())

    def _handle_yara_status_retro_scan_local(self, action_result, param):
        self.debug_print("Action handler", self.get_action_identifier())
        response = self.a1000.get_yara_local_retro_scan_status()
        self.debug_print("Executed", self.get_action_identifier())
        action_result.add_data(response.json())

    def _handle_yara_status_retro_scan_cloud(self, action_result, param):
        self.debug_print("Action handler", self.get_action_identifier())
        response = self.a1000.get_yara_cloud_retro_scan_status(
            ruleset_name=param.get("name"),
        )
        self.debug_print("Executed", self.get_action_identifier())
        action_result.add_data(response.json())

    def _handle_list_containers_for_hash(self, action_result, param):
        self.debug_print("Action handler", self.get_action_identifier())
        response = self.a1000.list_containers_for_hashes(
            sample_hashes=param.get("hash_values").strip().split(","),
        )
        self.debug_print("Executed", self.get_action_identifier())
        action_result.add_data(response.json())

    def _handle_delete_sample(self, action_result, param):
        self.debug_print("Action handler", self.get_action_identifier())
        response = self.a1000.delete_samples(
            hash_input=param.get("hash_value"),
        )
        self.debug_print("Executed", self.get_action_identifier())
        action_result.add_data(response.json())

    def _handle_download_extracted_files(self, action_result, param):
        self.debug_print("Action handler", self.get_action_identifier())
        response = self.a1000.download_extracted_files(
            sample_hash=param.get("hash_value"),
        )
        self.debug_print("Executed", self.get_action_identifier())

        file_path = os.path.join(Vault.get_vault_tmp_dir(), param.get("hash_value"))
        with open(file_path, "wb") as file_obj:
            file_obj.write(response.content)

        success, msg, vault_id = vault.vault_add(file_location=file_path,
                                                 container=self.get_container_id(),
                                                 file_name="extracted_from-{0}.zip".format(param.get("hash_value")))
        if not success:
            raise Exception('Unable to store file in Vault. Error details: {0}'.format(msg))

    def _handle_reanalyze_samples(self, action_result, param):
        self.debug_print("Action handler", self.get_action_identifier())
        response = self.a1000.reanalyze_samples_v2(
            hash_input=param.get("hash_value").strip().split(","),
            titanium_cloud=param.get("titanium_cloud", False),
            titanium_core=param.get("titanium_core", False),
            rl_cloud_sandbox=param.get("rl_cloud_sandbox", False),
            cuckoo_sandbox=param.get("cuckoo_sandbox", False),
            fireeye=param.get("fireeye", False),
            joe_sandbox=param.get("joe_sandbox", False),
            cape=param.get("cape", False),
            rl_cloud_sandbox_platform=param.get("rl_cloud_sandbox_platform"),
        )
        self.debug_print("Executed", self.get_action_identifier())
        action_result.add_data(response.json())


def main():
    import argparse

    argparser = argparse.ArgumentParser()
    args = argparser.parse_args()
    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)

        connector = ReversinglabsA1000V2Connector()
        connector.print_progress_message = True

        connector._handle_action(json.dumps(in_json), None)
    exit(0)


if __name__ == '__main__':
    main()
