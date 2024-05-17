# File: reversinglabs_a1000v2_views.py
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
def advanced_search(provides, all_app_runs, context):
    for summary, action_results in all_app_runs:
        for result in action_results:
            for x in result.get_data():
                x["classification_color"] = color_code_classification(x.get("classification").upper())
            context['data'] = result.get_data()
            context['results_found'] = f"Results found: {str(len(result.get_data()))}"
            context['param'] = result.get_param()

    return 'views/reversinglabs_advanced_search.html'


def get_classification(provides, all_app_runs, context):
    for summary, action_results in all_app_runs:
        for result in action_results:
            context['data'] = result.get_data()[0]
            context["classification"] = context['data'].get("classification", "UNAVAILABLE").upper()
            context["classification_color"] = color_code_classification(context["classification"])
    return 'views/reversinglabs_get_classification.html'


def get_detailed_report(provides, all_app_runs, context):
    for summary, action_results in all_app_runs:
        for result in action_results:
            context['data'] = result.get_data()[0]
            context["classification"] = context['data'].get('results')[0].get('classification').upper()
            context["classification_color"] = color_code_classification(context["classification"])
            context['param'] = result.get_param()

    return 'views/reversinglabs_get_detailed_report.html'


def get_summary_report(provides, all_app_runs, context):
    for summary, action_results in all_app_runs:
        for result in action_results:
            context['data'] = result.get_data()[0]
            context["classification"] = context['data'].get('results')[0].get('classification').upper()
            context["classification_color"] = color_code_classification(context["classification"])
            context['param'] = result.get_param()

    return 'views/reversinglabs_get_summary_report.html'


def get_titaniumcore_report(provides, all_app_runs, context):
    for summary, action_results in all_app_runs:
        for result in action_results:
            context['data'] = result.get_data()[0]
            context["classification"] = get_status_from_ticore_classification(
                context['data'].get("classification").get("classification")
            ).upper()
            context["classification_color"] = color_code_classification(context["classification"])
            context['param'] = result.get_param()

    return 'views/reversinglabs_get_titaniumcore_report.html'


def url_reputation(provides, all_app_runs, context):
    for summary, action_results in all_app_runs:
        for result in action_results:
            context['data'] = result.get_data()[0]
            context["classification"] = context['data'].get("classification", "UNAVAILABLE").upper()
            context["classification_color"] = color_code_classification(context["classification"])

    return 'views/reversinglabs_url_reputation.html'


def domain_reputation(provides, all_app_runs, context):
    for summary, action_results in all_app_runs:
        for result in action_results:
            context['data'] = result.get_data()[0]

    return 'views/reversinglabs_domain_reputation.html'


def ip_reputation(provides, all_app_runs, context):
    for summary, action_results in all_app_runs:
        for result in action_results:
            context['data'] = result.get_data()[0]

    return 'views/reversinglabs_ip_reputation.html'


def network_ip_to_domain(provides, all_app_runs, context):
    for summary, action_results in all_app_runs:
        for result in action_results:
            context['data'] = result.get_data()[0]

    return 'views/reversinglabs_network_ip_to_domain.html'


def network_urls_from_ip(provides, all_app_runs, context):
    for summary, action_results in all_app_runs:
        for result in action_results:
            context['data'] = result.get_data()[0]

    return 'views/reversinglabs_network_urls_from_ip.html'


def network_files_from_ip(provides, all_app_runs, context):
    for summary, action_results in all_app_runs:
        for result in action_results:
            context['data'] = result.get_data()[0]
            for x in context['data'].get("downloaded_files"):
                x["classification_color"] = color_code_classification(x.get("classification").upper())

    return 'views/reversinglabs_network_files_from_ip.html'


def check_dynamic_analysis_report_status(provides, all_app_runs, context):
    for summary, action_results in all_app_runs:
        for result in action_results:
            context['data'] = result.get_data()[0]
            context['param'] = result.get_param()

    return 'views/reversinglabs_check_dynamic_analysis_report_status.html'


def check_pdf_report_status(provides, all_app_runs, context):
    for summary, action_results in all_app_runs:
        for result in action_results:
            context['data'] = result.get_data()[0]
            context['param'] = result.get_param()

    return 'views/reversinglabs_check_pdf_report_status.html'


def check_submitted_url_status(provides, all_app_runs, context):
    for summary, action_results in all_app_runs:
        for result in action_results:
            context['data'] = result.get_data()[0]
            context['param'] = result.get_param()
            if context['data'].get('report', {}).get('sample_summary', {}).get('classification', {}):
                classification = context['data']['report']['sample_summary']['classification'].upper()
                context['classification_color'] = color_code_classification(classification)
                context['classification'] = classification

    return 'views/reversinglabs_check_submitted_url_status.html'


def submit_url(provides, all_app_runs, context):
    for summary, action_results in all_app_runs:
        for result in action_results:
            context['data'] = result.get_data()[0]
            context['param'] = result.get_param()

    return 'views/reversinglabs_submit_url.html'


def retrieve_user_tags(provides, all_app_runs, context):
    for summary, action_results in all_app_runs:
        for result in action_results:
            context['data'] = result.get_data()[0]
            context['param'] = result.get_param()

    return 'views/reversinglabs_retrieve_user_tags.html'


def create_user_tags(provides, all_app_runs, context):
    for summary, action_results in all_app_runs:
        for result in action_results:
            context['data'] = result.get_data()[0]
            context['param'] = result.get_param()

    return 'views/reversinglabs_create_user_tags.html'


def delete_user_tags(provides, all_app_runs, context):
    for summary, action_results in all_app_runs:
        for result in action_results:
            context['data'] = result.get_data()[0]
            context['param'] = result.get_param()

    return 'views/reversinglabs_delete_user_tags.html'


def set_sample_classification(provides, all_app_runs, context):
    for summary, action_results in all_app_runs:
        for result in action_results:
            data = result.get_data()[0]
            context["param"] = result.get_param()
            context['data'] = data
            if data["source"] == "local":
                classification = data.get("classification", "UNAVAILABLE").upper()
                context["classification_color"] = color_code_classification(classification)

    return 'views/reversinglabs_set_sample_classification.html'


def delete_sample_classification(provides, all_app_runs, context):
    for summary, action_results in all_app_runs:
        for result in action_results:
            data = result.get_data()[0]
            context["param"] = result.get_param()
            context['data'] = data

    return 'views/reversinglabs_delete_sample_classification.html'


def yara_get_rules(provides, all_app_runs, context):
    for summary, action_results in all_app_runs:
        for result in action_results:
            context["data"] = result.get_data()
            context["param"] = result.get_param()
    return 'views/reversinglabs_yara_get_rules.html'


def yara_get_rule_content(provides, all_app_runs, context):
    for summary, action_results in all_app_runs:
        for result in action_results:
            context["data"] = result.get_data()
            context["param"] = result.get_param()
    return 'views/reversinglabs_yara_get_rule_content.html'


def yara_get_matches(provides, all_app_runs, context):
    for summary, action_results in all_app_runs:
        for result in action_results:
            context["data"] = result.get_data()
            context["param"] = result.get_param()
    return 'views/reversinglabs_yara_get_matches.html'


def yara_create_rule(provides, all_app_runs, context):
    for summary, action_results in all_app_runs:
        for result in action_results:
            context["data"] = result.get_data()
            context["param"] = result.get_param()
    return 'views/reversinglabs_yara_create_rule.html'


def yara_delete_rule(provides, all_app_runs, context):
    for summary, action_results in all_app_runs:
        for result in action_results:
            context["data"] = result.get_data()
            context["param"] = result.get_param()
    return 'views/reversinglabs_yara_delete_rule.html'


def yara_toggle_rule(provides, all_app_runs, context):
    for summary, action_results in all_app_runs:
        for result in action_results:
            context["data"] = result.get_data()
            context["param"] = result.get_param()
    return 'views/reversinglabs_yara_toggle_rule.html'


def color_code_classification(classification):
    color = ""
    classification = classification.upper()
    if classification == 'MALICIOUS':
        color = "red"
    elif classification == 'SUSPICIOUS':
        color = "orange"
    elif classification == 'KNOWN':
        color = "green"
    elif classification == 'GOODWARE':
        color = "green"

    return color


def get_status_from_ticore_classification(classification_int):
    status_mapping = {
        3: "malicious",
        2: "suspicious",
        1: "known"
    }

    return status_mapping.get(classification_int, 'unknown')
