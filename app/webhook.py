from flask import Flask, request, jsonify
from os import environ
import logging
import json
import zipfile
import tempfile
import requests
import pandas as pd
import datetime

webhook = Flask(__name__)

webhook.config['TOKEN'] = environ.get('TOKEN')
webhook.config['SSL'] = environ.get('SSL')

webhook.logger.setLevel(logging.INFO)
global token
global all_queried_vulnid_list
all_queried_vulnid_list = []
global matched_item
matched_item = {}

if "TOKEN" not in environ:
    webhook.logger.error("Please add the TOKEN environment variable via Secret. Exiting...")
    exit(1)


@webhook.route('/webhook', methods=['POST'])
def webhook_handler():
    request_body = request.get_json()
    webhook.logger.info(f'The request body {request_body}')

    if request_body is None:
        webhook.logger.info(f'The request body is {request_body}')
        return webhook_response(True, f"{request_body}")
    else:
        if "url" in request_body['event'].keys():
            url = request_body['event']['url']

            if "scanning/reports" in url:
                webhook.logger.info(f'The request body is {request_body}')
                webhook.logger.info(f'The URL to work with {url}')

                return json_file_report_downloader(url, request_body['event']['eventData']['name'])
        else:
            webhook.logger.info(f'There is no URL to work with')
            return webhook_response(True, f"There is no URL to work with")


def json_file_report_downloader(url, report_name):
    try:
        token = webhook.config['TOKEN']
    except Exception as e:
        webhook.logger.error(f'{e}')
        exit(1)

    try:
        ssl_enable = webhook.config['SSL']
        if ssl_enable == 'yes':
            ssl_off = {'verify': True}
        else:
            ssl_off = {'verify': False}

        with requests.get(url, headers={'Authorization': 'Bearer {}'.format(token)}, allow_redirects=True, stream=True,
                          **ssl_off) as response:

            webhook.logger.info(f'Response Code: {response.status_code}')
            webhook.logger.info(f'Response Headers: {response.headers}')

            if "scanning/reports" in url:
                with tempfile.TemporaryFile() as archive_ref:
                    for chunk in response.iter_content(chunk_size=None):
                        if chunk:
                            archive_ref.write(chunk)
                    archive_ref.seek(0)
                    with zipfile.ZipFile(archive_ref) as myzip:
                        infolist = myzip.infolist()
                        report_file = myzip.open(infolist[0])
                        data = json.load(report_file)
                        data = json_flatten_runtime_info(data)
                        return json_convert_vulndb_to_cve(data, report_name)

    except requests.exceptions.RequestException as e:
        webhook.logger.info(f'Reason: {e}')
        return webhook_response(True, f"Internal Error - Reason: {e}")


def json_convert_vulndb_to_cve(report, report_name):
    all_queried_vulnid_list.clear()
    csv_data_list = []
    vulnId_cveId_data_list = []
    vulnId_cveId_data_dict = {}
    csv_data_dict = {}

    for item in report:
        csv_data_dict["Vulnerability ID"] = item["vulnId"]
        csv_data_dict["Severity"] = item["vulnSeverity"]
        csv_data_dict["Package name"] = item["packageName"]
        csv_data_dict["Image ID"] = item["imageId"]
        csv_data_dict["Image name"] = item["imageName"]
        csv_data_dict["Image tag"] = item["imageTag"]
        csv_data_dict["Vulnerability type"] = item["vulnType"]
        csv_data_dict["CVSS v2 vector"] = item["vulnCvss2Vector"]
        csv_data_dict["CVSS v2 base score"] = item["vulnCvss2Score"]
        csv_data_dict["CVSS v3 vector"] = item["vulnCvss3Vector"]
        csv_data_dict["CVSS v3 base score"] = item["vulnCvss3Score"]
        csv_data_dict["Vuln link"] = item["vulnLink"]
        csv_data_dict["Disclosure date"] = item["vulnDisclosureDate"]
        csv_data_dict["Solution date"] = item["vulnSolutionDate"]
        csv_data_dict["Fix version"] = item["vulnFixVersion"]
        csv_data_dict["Vuln exception"] = item["vulnException"]
        csv_data_dict["Package version"] = item["packageVersion"]
        csv_data_dict["Package path"] = item["packagePath"]
        csv_data_dict["Image added"] = item["imageAddedAt"]
        csv_data_dict["Pod"] = item["pod"]
        csv_data_dict["Namespace"] = item["namespace"]
        csv_data_dict["Container Name"] = item["container_name"]
        csv_data_dict["Container ID"] = item["container_id"]
        csv_data_dict["Cluster Name"] = item["cluster_name"]
        csv_data_dict["Deployment"] = item["deployment"]
        csv_data_dict["Hostname"] = item["hostname"]

        if "CVE" not in item['vulnId']:
            if item['vulnId'] not in all_queried_vulnid_list:
                print(item['vulnId'])
                converted_vuln_data = convert_to_cve(item['vulnId'])
                converted_nvd_data = converted_vuln_data["nvd_data"][0]
                csv_data_dict["Vulnerability ID"] = converted_nvd_data["id"]
                if converted_nvd_data["cvss_v2"] is not None:
                    csv_data_dict["CVSS v2 vector"] = converted_nvd_data["cvss_v2"]["vector_string"]
                    csv_data_dict["CVSS v2 base score"] = converted_nvd_data["cvss_v2"]["base_metrics"]["base_score"]
                    csv_data_dict["Severity"] = converted_nvd_data["cvss_v2"]["severity"]
                else:
                    csv_data_dict["CVSS v2 vector"] = ""
                    csv_data_dict["CVSS v2 base score"] = ""
                if converted_nvd_data["cvss_v3"] is not None:
                    csv_data_dict["CVSS v3 vector"] = converted_nvd_data["cvss_v3"]["vector_string"]
                    csv_data_dict["CVSS v3 base score"] = converted_nvd_data["cvss_v2"]["base_metrics"]["base_score"]
                    csv_data_dict["Severity"] = converted_nvd_data["cvss_v3"]["severity"]
                else:
                    csv_data_dict["CVSS v3 vector"] = ""
                    csv_data_dict["CVSS v3 base score"] = ""
                csv_data_dict["Vuln link"] = converted_vuln_data["references"][0]["url"]
                all_queried_vulnid_list.append(item['vulnId'])
                vulnId_cveId_data_dict['vulnId'] = item['vulnId']
                vulnId_cveId_data_dict['cveId'] = csv_data_dict["Vulnerability ID"]
                vulnId_cveId_data_dict["CVSS v2 vector"] = csv_data_dict["CVSS v2 vector"]
                vulnId_cveId_data_dict["CVSS v3 vector"] = csv_data_dict["CVSS v3 vector"]
                vulnId_cveId_data_dict["CVSS v2 base score"] = csv_data_dict["CVSS v2 base score"]
                vulnId_cveId_data_dict["CVSS v3 base score"] = csv_data_dict["CVSS v3 base score"]
                vulnId_cveId_data_dict["Vuln link"] = csv_data_dict["Vuln link"]
                vulnId_cveId_data_dict["Severity"] = csv_data_dict["Severity"]
                vulnId_cveId_data_list.append(vulnId_cveId_data_dict.copy())
                vulnId_cveId_data_dict.clear()
            else:
                print("Already found vuln id, not querying again!")
                try:
                    matched_item = next(x for x in vulnId_cveId_data_list if x['vulnId'] == item['vulnId'])
                    csv_data_dict["Vulnerability ID"] = matched_item['cveId']
                    csv_data_dict["CVSS v2 vector"] = matched_item["CVSS v2 vector"]
                    csv_data_dict["CVSS v2 base score"] = matched_item["CVSS v2 base score"]
                    csv_data_dict["CVSS v3 vector"] = matched_item["CVSS v3 vector"]
                    csv_data_dict["CVSS v3 base score"] = matched_item["CVSS v3 base score"]
                    csv_data_dict["Vuln link"] = matched_item["Vuln link"]
                    csv_data_dict["Severity"] = matched_item["Severity"]
                except Exception as e:
                    webhook.logger.info(f'Reason: {e}')

        csv_data_list.append(csv_data_dict.copy())

    print(csv_data_list)

    return convert_to_csv(csv_data_list, report_name)


def convert_to_csv(final_list, report_name):
    df = pd.DataFrame(final_list)
    df.to_csv(report_name + f'{datetime.datetime.now():_%Y-%m-%d_%H:%M}' + ".csv", index=False)
    return webhook_response(True, f"done")


def convert_to_cve(vulndb_id):
    url = "https://secure.sysdig.com/api/scanning/v1/anchore/query/vulnerabilities?id=" + vulndb_id
    print(url)
    payload = ""
    headers = {
        'Authorization': 'Bearer 665582ce-b57d-40ab-a593-1a115ec9c5fa'
    }
    response = requests.request("GET", url, headers=headers, data=payload)
    if response.status_code == 200:
        vuln_data = json.loads(response.text)
        vuln_data = vuln_data["vulnerabilities"][0]
    return vuln_data


def json_flatten_runtime_info(report):
    flattened_report = []

    for item in report['data']:
        data = item.copy()
        del data['runtimeInfo']
        for runtime_info in item['runtimeInfo']:
            runtime_data = data.copy()
            runtime_data.update(runtime_info)
            flattened_report.append(runtime_data)

    return flattened_report


def webhook_response(allowed, message):
    return jsonify({"response": "I got it"})


if __name__ == '__main__':
    webhook.run(host='0.0.0.0', port=5000)
