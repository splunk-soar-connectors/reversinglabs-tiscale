# File: tiscale_connector.py
#
# Copyright (c) 2016-2022 Splunk Inc.
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
#
# Phantom imports
import phantom.app as phantom
import phantom.rules as ph_rules
from phantom.app import ActionResult, BaseConnector

try:
    from phantom.vault import Vault
except BaseException:
    import phantom.vault as Vault

import inspect
import json
# Other imports used by this connector
import os
import re
import time

import phantom.utils as ph_utils
import requests
# Wheels import
from rl_threat_hunting import file_report, tc_metadata_adapter

from tiscale_consts import *


class TISCALEConnector(BaseConnector):

    # The actions supported by this connector
    ACTION_ID_DETONATE_FILE = "detonate_file"
    ACTION_ID_DETONATE_URL = "detonate_url"
    ACTION_ID_GET_REPORT = "get_report"
    ACTION_ID_GET_SAMPLE = "get_sample"
    ACTION_ID_GET_PCAP = "get_pcap"
    ACTION_ID_TEST_ASSET_CONNECTIVITY = 'test_asset_connectivity'

    MAGIC_FORMATS = [
      (re.compile('^PE.* Windows'), ['pe file'], '.exe'),
      (re.compile('^MS-DOS executable'), ['pe file'], '.exe'),
      (re.compile('^PDF '), ['pdf'], '.pdf'),
      (re.compile('^MDMP crash'), ['process dump'], '.dmp'),
      (re.compile('^Macromedia Flash'), ['flash'], '.flv'),
      (re.compile('^tcpdump capture'), ['pcap'], '.pcap'),
    ]

    FILE_UPLOAD_ERROR_DESC = {
            '401': 'API key invalid',
            '405': 'HTTP method Not Allowed',
            '413': 'Sample file size over max limit',
            '418': 'Sample file type is not supported',
            '419': 'Max number of uploads per day exceeded',
            '422': 'URL download error',
            '500': 'Internal error',
            '513': 'File upload failed'}

    GET_REPORT_ERROR_DESC = {
            '401': 'API key invalid',
            '404': 'The report was not found',
            '405': 'HTTP method Not Allowed',
            '419': 'Request report quota exceeded',
            '420': 'Insufficient arguments',
            '421': 'Invalid arguments',
            '500': 'Internal error'}

    GET_SAMPLE_ERROR_DESC = {
            '401': 'API key invalid',
            '403': 'Permission Denied',
            '404': 'The sample was not found',
            '405': 'HTTP method Not Allowed',
            '419': 'Request sample quota exceeded',
            '420': 'Insufficient arguments',
            '421': 'Invalid arguments',
            '500': 'Internal error'}

    GET_PCAP_ERROR_DESC = {
            '401': 'API key invalid',
            '403': 'Permission Denied',
            '404': 'The pcap was not found',
            '405': 'HTTP method Not Allowed',
            '419': 'Request sample quota exceeded',
            '420': 'Insufficient arguments',
            '421': 'Invalid arguments',
            '500': 'Internal error'}

    PLATFORM_ID_MAPPING = {
            'Default': None,
            'Win XP, Adobe 9.3.3, Office 2003': 1,
            'Win XP, Adobe 9.4.0, Flash 10, Office 2007': 2,
            'Win XP, Adobe 11, Flash 11, Office 2010': 3,
            'Win 7 32-bit, Adobe 11, Flash11, Office 2010': 4,
            'Win 7 64 bit, Adobe 11, Flash 11, Office 2010': 5,
            'Android 2.3, API 10, avd2.3.1': 201}

    def __init__(self):

        # Call the BaseConnectors init first
        super(TISCALEConnector, self).__init__()

        self._api_token = None

    def initialize(self):

        config = self.get_config()

        # Base URL
        self._base_url = config[TISCALE_JSON_BASE_URL]
        if (self._base_url.endswith('/')):
            self._base_url = self._base_url[:-1]

        self._host = self._base_url[self._base_url.find('//') + 2:]

        # self._req_sess = requests.Session()

        return phantom.APP_SUCCESS

    def _parse_report_status_msg(self, response, action_result, data):

        reports = {}

        if (not isinstance(reports, list)):
            reports = [response]

        # pprint.pprint(response)
        response1 = {}
        response1['task_info'] = {}
        response1['task_info']['report'] = reports

        for report in response['tc_report']:
            try:
                report['temp_indicators'] = []
                report['application'] = self._normalize_children_into_list(
                    response.get('application'))
                for i in response.get('indicators'):
                    report['temp_indicators'].append(
                        self._normalize_children_into_list(i))
                report['indicators'] = report['temp_indicators']
            except BaseException:
                pass
            try:
                report['temp_indicators'] = []
                for i in response.get('interesting_strings'):
                    report['temp_indicators'].append(
                        self._normalize_children_into_list(i))
                report['interesting_strings'] = report['temp_indicators']
            except BaseException:
                pass
            try:
                report['temp_indicators'] = []
                for i in response.get('certificate').get('certificates'):
                    report['temp_indicators'].append(
                        self._normalize_children_into_list(i))
                report['certificate'] = report['temp_indicators']
            except BaseException:
                pass
            try:
                report['temp_indicators'] = []
                # need to modify the summary to contain a dictionary
                sum_entries = response.get('summary', {}).get('entry')
                if (sum_entries):
                    for i, entry in enumerate(sum_entries):
                        if (not isinstance(entry, dict)):
                            sum_entries[i] = {
                                '#text': entry, '@details': 'N/A',
                                '@score': 'N/A', '@id': 'N/A'}
            except BaseException:
                pass

        # pprint.pprint(response)
        response1['tiscale_link'] = "{0}{1}".format(
            self._base_url, "?q=" + data['hash'])
        print("TISCALE link:" + str(response1['tiscale_link']))
        return response1

    def _parse_error(self, response, result, error_desc):

        status_code = response.status_code
        detail = response.text

        if (detail):
            return result.set_status(
                phantom.APP_ERROR,
                TISCALE_ERR_REST_API.format(
                    status_code=status_code,
                    detail=json.loads(detail)['message']))

        if (not error_desc):
            return result.set_status(
                phantom.APP_ERROR, TISCALE_ERR_REST_API.format(
                    status_code=status_code, detail='N/A'))

        detail = error_desc.get(str(status_code))

        if (not detail):
            # no detail
            return result.set_status(
                phantom.APP_ERROR, TISCALE_ERR_REST_API.format(
                    status_code=status_code, detail='N/A'))

        return result.set_status(
            phantom.APP_ERROR,
            TISCALE_ERR_REST_API.format(
                status_code=status_code,
                detail=detail))

    def _make_rest_call(
            self,
            endpoint,
            result,
            error_desc,
            method="get",
            params={},
            data={},
            filein=None,
            files=None,
            parse_response=True,
            additional_succ_codes={}):

        url = "{0}{1}".format(self._base_url, endpoint)

        config = self.get_config()

        # request_func = getattr(self._req_sess, method)

        # if (not request_func):
        # return (result.set_status(phantom.APP_ERROR, "Invalid method call: {0}
        # for requests module".format(method)), None)

        if (files is None):
            files = dict()

        if (filein is not None):
            files = {'file': filein}

        if method == 'post':
            try:
                if(TISCALE_JSON_API_KEY in config):
                    # r = request_func(url, params=params, data=data, files=files, verify=config[phantom.APP_JSON_VERIFY])
                    r = requests.post(url, files=files, timeout=10, headers={
                                      'Authorization': 'Token %s' % config[TISCALE_JSON_API_KEY],
                                      'User-Agent': 'ReversingLabs Phantom TiScale v2.2'})
                else:
                    r = requests.post(url,
                                      files=files,
                                      timeout=10,
                                      headers={'User-Agent': 'ReversingLabs Phantom TiScale v2.2'})

            except Exception as e:
                return (
                    result.set_status(
                        phantom.APP_ERROR,
                        "REST POST Api to server failed " + str(e),
                        e),
                    None)
        else:
            try:
                # r = request_func(url, params=params, data=data, files=files, verify=config[phantom.APP_JSON_VERIFY])
                url = endpoint
                result.add_debug_data({'r_text': url})
                if(TISCALE_JSON_API_KEY in config):
                    r = requests.get(
                        url,
                        timeout=10,
                        headers={
                            'Authorization': 'Token %s' % config[TISCALE_JSON_API_KEY],
                            'User-Agent': 'ReversingLabs Phantom TiScale v2.2'})
                else:
                    r = requests.get(url, timeout=10, headers={'User-Agent': 'ReversingLabs Phantom TiScale v2.2'})
            except Exception as e:
                return (
                    result.set_status(
                        phantom.APP_ERROR,
                        "REST GET Api to server failed " + str(e) + " url: " + url,
                        e),
                    None)

        # It's ok if r.text is None, dump that
        if (hasattr(result, 'add_debug_data')):
            result.add_debug_data({'r_text': r.text if r else 'r is None'})
        # import pdb;pdb.set_trace()
        if (r.status_code in additional_succ_codes):
            response = additional_succ_codes[r.status_code]
            return (
                phantom.APP_SUCCESS,
                response if response is not None else r.text)

        # Look for errors
        if r.status_code in [404]:  # pylint: disable=E1101
            self._parse_error(r, result, error_desc)
            return (result.get_status(), r.text)

        if (not parse_response):
            return (phantom.APP_SUCCESS, r)

        response_dict = json.loads(r.text)

        return (phantom.APP_SUCCESS, response_dict)

    def _get_file_dict(self, param, action_result):

        vault_id = param[TISCALE_JSON_VAULT_ID]

        filename = param.get('file_name')
        if not filename:
            filename = vault_id

        try:
            success, msg, files_array = ph_rules.vault_info(vault_id=vault_id)
            if not success:
                return (action_result.set_status(phantom.APP_ERROR,
                        f'Unable to get Vault item details. Error Details: {msg}'),
                        None)
            file_data = list(files_array)[0]
            payload = open(file_data['path'], 'rb').read()

        except BaseException:
            return (
                action_result.set_status(
                    phantom.APP_ERROR,
                    'File not found in vault ("{}")'.format(vault_id)),
                None)

        files = {'file': (filename, payload)}

        return (phantom.APP_SUCCESS, files)

    def _test_connectivity(self, param):
        # get the file from the app directory
        dirpath = os.path.dirname(inspect.getfile(self.__class__))
        filename = TISCALE_TEST_PDF_FILE

        filepath = "{}/{}".format(dirpath, filename)

        try:
            payload = open(filepath, 'rb')
        except BaseException:
            self.set_status(phantom.APP_ERROR,
                            'Test pdf file not found at "{}"'.format(filepath))
            self.append_to_message('Test Connectivity failed')
            return self.get_status()

        try:
            self.save_progress(
                'Detonating test pdf file for checking connectivity')
            files = payload
            ret_val, response = self._make_rest_call(
                '/api/tiscale/v1/upload', self, self.FILE_UPLOAD_ERROR_DESC,
                method='post', filein=files)
        except BaseException:
            self.set_status(
                phantom.APP_ERROR,
                'Connectivity failed, check the server name and API key.\n')
            self.append_to_message('Test Connectivity failed.\n')
            return self.get_status()

        if (phantom.is_fail(ret_val)):
            self.append_to_message('Test Connectivity Failed')
            return self.get_status()

        return self.set_status_save_progress(
            phantom.APP_SUCCESS, 'Test Connectivity Passed')

    def _normalize_into_list(self, input_dict, key):
        if (not input_dict):
            return None

        if (key not in input_dict):
            return None

        if (type(input_dict[key] != list)):
            input_dict[key] = [input_dict[key]]
        input_dict[key.lower()] = input_dict.pop(key)

        return input_dict

    def _normalize_children_into_list(self, input_dict):

        if (not input_dict):
            return {}

        for key in input_dict.keys():
            if (not isinstance(input_dict[key], list)):
                input_dict[key] = [input_dict[key]]
            input_dict[key.lower()] = input_dict.pop(key)

        return input_dict

    def _check_detonated_report(self, task_id, action_result):
        """This function is different than other functions that get the report
        since it is supposed to check just once and return, also treat a 404 as error
        """

        data = {'hash': task_id}

        ret_val, response = self._make_rest_call(
            '/api/samples/', action_result, self.GET_REPORT_ERROR_DESC,
            method='get', data=data)

        if (phantom.is_fail(ret_val)):
            return (action_result.get_status(), None)

        # parse if successfull
        # response = self._parse_report_status_msg(response, action_result, data)

        if (response):
            return (phantom.APP_SUCCESS, response)

        return (phantom.APP_ERROR, None)

    def _poll_task_status(self, task_id, action_result, full_report=False):
        polling_attempt = 0

        config = self.get_config()

        timeout = config[TISCALE_JSON_POLL_TIMEOUT_MINS]

        if (not timeout):
            timeout = TISCALE_MAX_TIMEOUT_DEF

        max_polling_attempts = (int(timeout) * 60) / TISCALE_SLEEP_SECS

        data = {'hash': task_id}

        while (polling_attempt < max_polling_attempts):

            polling_attempt += 1

            self.save_progress(
                "Polling attempt {0} of {1}".format(
                    polling_attempt,
                    max_polling_attempts))

            endpoint = '{}?full=true'.format(task_id) if full_report else task_id
            ret_val, response = self._make_rest_call(
                endpoint,
                action_result, self.GET_REPORT_ERROR_DESC,
                method='get', data=data,
                additional_succ_codes={404: TISCALE_MSG_REPORT_PENDING})

            if (phantom.is_fail(ret_val)):
                return (action_result.get_status(), None)

            if (response['processed'] is None):
                time.sleep(TISCALE_SLEEP_SECS)
                continue

            if (phantom.is_success(ret_val)):
                # Add a data dictionary into the result to store information
                action_result.add_data({'tiscale_report': response})

                self._handle_samples(action_result, response)

                # parse if successfull
                # response = self._parse_report_status_msg(response, action_result, data)

                if (response):
                    return (phantom.APP_SUCCESS, response)

            time.sleep(TISCALE_SLEEP_SECS)

        self.save_progress("Reached max polling attempts.")

        return (
            action_result.set_status(
                phantom.APP_ERROR,
                TISCALE_MSG_MAX_POLLS_REACHED),
            None)

    def _get_platform_id(self, param):

        platform = param.get(TISCALE_JSON_PLATFORM)

        if (not platform):
            return None

        platform = platform.upper()

        if (platform not in self.PLATFORM_ID_MAPPING):
            return None

        return self.PLATFORM_ID_MAPPING[platform]

    def validate_parameters(self, param):
        """Do our own validations instead of BaseConnector doing it for us"""

        action = self.get_action_identifier()

        if (action == self.ACTION_ID_DETONATE_URL):

            # add an http if not present
            url = param[TISCALE_JSON_URL]
            if ('://' not in url):
                url = "http://{0}".format(url)

            if (not ph_utils.is_url(url)):
                return phantom.APP_ERROR

            param[TISCALE_JSON_URL] = url

        return phantom.APP_SUCCESS

    def _detonate_file(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, files = self._get_file_dict(param, action_result)

        threat_hunting_state = self._get_threat_hunting_state(param)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        data = action_result.add_data({})

        # Was not detonated before
        self.save_progress('Uploading the file')

        # upload the file to the upload service
        ret_val, response = self._make_rest_call(
            '/api/tiscale/v1/upload', action_result, self.FILE_UPLOAD_ERROR_DESC, method='post', filein=files['file'][1])

        # Was not detonated before
        self.save_progress('Uploaded the file ' + str(ret_val))

        if (phantom.is_fail(ret_val)):
            return self.get_status()

        # The first part is the uploaded file info
        data.update(response)

        # get the sha1
        task_id = response.get('task_url')
        full_report = param.get('full_report')
        # import pdb;pdb.set_trace()

        # Now poll for the result
        ret_val, response = self._poll_task_status(task_id, action_result, full_report)

        if response is not None:
            hunting_meta = tc_metadata_adapter.parse_tc_metadata(response, threat_hunting_state)
            hunting_meta_vault_id = self._store_threat_hunting_state(hunting_meta)
            self._update_threat_hunting_state(action_result, hunting_meta, hunting_meta_vault_id)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # Add the report
        data.update(response)

        return action_result.set_status(phantom.APP_SUCCESS)

    @staticmethod
    def _get_threat_hunting_state(parameters):
        hunting_report_vault_id = parameters.get(TISCALE_JSON_HUNTING_STATE)
        if hunting_report_vault_id:
            success, msg, files_array = ph_rules.vault_info(vault_id=hunting_report_vault_id)
            file_data = list(files_array)[0]
            payload = open(file_data['path'], 'rb').read()
            return json.loads(payload.decode('utf-8'))

    def _store_threat_hunting_state(self, hunting_meta):
        container_id = self.get_container_id()
        vault_file_name = self._create_hunting_report_name()
        dump_path = self._dump_report_in_file(hunting_meta, vault_file_name)
        success, message, vault_id = ph_rules.vault_add(container_id, dump_path, file_name=vault_file_name)

        if success:
            return vault_id
        else:
            raise VaultError('Storing threat hunting report failed: ' + message)

    def _create_hunting_report_name(self):
        product_name = self._get_product_name()
        action_name = self._get_action_name()
        return '{}_{}_hunting_report.json'.format(product_name, action_name)

    def _get_product_name(self):
        app_config = self.get_app_json()
        product_name = app_config['product_name']
        return product_name.replace(' ', '_')

    def _get_action_name(self):
        action_name = self.get_action_name()
        return action_name.replace(' ', '_')

    @staticmethod
    def _dump_report_in_file(hunting_meta, file_name):
        dump_dir = Vault.get_vault_tmp_dir()
        dump_path = '{}/{}'.format(dump_dir, file_name)
        return file_report.write_json(hunting_meta, dump_path)

    @staticmethod
    def _update_threat_hunting_state(action_result, hunting_report, hunting_report_vault_id):
        action_result.add_data(hunting_report)
        action_result.add_data({TISCALE_JSON_HUNTING_STATE: hunting_report_vault_id})

    def _handle_samples(self, action_result, samples):
        if (not samples):
            return

        try:
            status = samples['tc_report'][0]['classification']['classification']
            if(status == 3):
                status = 'MALICIOUS'
            elif(status == 2):
                status = 'SUSPICIOUS'
            elif(status == 1):
                status = 'KNOWN'
            elif(status == 0):
                status = 'UNKNOWN'
            action_result.update_summary({'classification': status})
        except:
            action_result.update_summary({'classification': "UNKNOWN"})
            return

        return

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS
        # Get the action that we are supposed to execute for this connector run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if (action_id == self.ACTION_ID_DETONATE_FILE):
            ret_val = self._detonate_file(param)
        elif (action_id == self.ACTION_ID_TEST_ASSET_CONNECTIVITY):
            ret_val = self._test_connectivity(param)
        return ret_val


class VaultError(Exception):
    pass


if __name__ == '__main__':

    import sys

    if (len(sys.argv) < 2):
        print("No test json specified as input")
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = TISCALEConnector()
        connector.print_progress_message = True
        injson = json.dumps(in_json)
        ret_val = connector._handle_action(injson, None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)
