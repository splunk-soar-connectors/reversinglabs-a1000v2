#!/usr/bin/python
# -*- coding: utf-8 -*-
# -----------------------------------------
# Phantom sample App Connector python file
# -----------------------------------------

# Python 3 Compatibility imports
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


class ReversinglabsA1000Connector(BaseConnector):
    post_url = "post_url"
    USER_AGENT = "ReversingLabs A1000 v1.0.0"
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

    def __init__(self):
        # Call the BaseConnectors init first
        super(ReversinglabsA1000Connector, self).__init__()

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
            self.ACTION_ID_GET_CLASSIFICATION: self._handle_get_classification
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

    def _handle_create_dynamic_analysis_report(self, action_result,  param):
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
        self.a1000.test_connection()

        self.save_progress("Test Connectivity Passed")


def main():
    import argparse

    argparser = argparse.ArgumentParser()
    args = argparser.parse_args()
    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)

        connector = ReversinglabsA1000Connector()
        connector.print_progress_message = True

        connector._handle_action(json.dumps(in_json), None)
    exit(0)


if __name__ == '__main__':
    main()
