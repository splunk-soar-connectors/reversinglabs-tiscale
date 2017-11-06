# --
#
# Copyright (c) ReversingLabs Inc 2016Copyright (c) ReversingLabs Inc 2016-2017
#
# This unpublished material is proprietary to ReversingLabs Inc.
# All rights reserved.
# Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of ReversingLabs Inc.
#
# --

# Phantom imports
import phantom.app as phantom
from phantom.app import BaseConnector
from phantom.app import ActionResult
try:
    from phantom.vault import Vault
except BaseException:
    import phantom.vault as Vault

import phantom.utils as ph_utils

from tiscale_consts import *

# Other imports used by this connector
import os
import time
import inspect
import json
import requests
# import xmltodict
import uuid
import re
import magic
import shutil

try:
    requests.packages.urllib3.disable_warnings()
except:
    pass


def __unicode__(self):
    return unicode(self.some_field) or u''


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
        print "TISCALE link:" + response1['tiscale_link']
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
            parse_response=True,
            additional_succ_codes={}):

        url = "{0}{1}".format(self._base_url, endpoint)

        config = self.get_config()

        # request_func = getattr(self._req_sess, method)

        # if (not request_func):
        # return (result.set_status(phantom.APP_ERROR, "Invalid method call: {0}
        # for requests module".format(method)), None)

        if method == 'post':
            try:
                if(TISCALE_JSON_API_KEY in config):
                    # r = request_func(url, params=params, data=data, files=files, verify=config[phantom.APP_JSON_VERIFY])
                    r = requests.post(url, files={'file': filein}, headers={
                                      'Authorization': 'Token %s' % config[TISCALE_JSON_API_KEY]})
                else:
                    r = requests.post(url,
                                      files={'file': filein})

            except Exception as e:
                return (
                    result.set_status(
                        phantom.APP_ERROR,
                        "REST POST Api to server failed " +
                        str(e),
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
                        headers={
                            'Authorization': 'Token %s' % config[TISCALE_JSON_API_KEY]})
                else:
                    r = requests.get(url)
            except Exception as e:
                return (
                    result.set_status(
                        phantom.APP_ERROR,
                        "REST GET Api to server failed " +
                        str(e) +
                        " url: " +
                        url,
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

        vault_id = param['vault_id']

        filename = param.get('file_name')
        if not filename:
            filename = vault_id

        try:
            if (hasattr(Vault, 'get_file_path')):
                payload = open(Vault.get_file_path(vault_id), 'rb')
            else:
                payload = open(
                    Vault.get_vault_file(vault_id),
                    'rb')  # pylint: disable=E1101
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

    def _poll_task_status(self, task_id, action_result):
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

            ret_val, response = self._make_rest_call(
                task_id, action_result, self.GET_REPORT_ERROR_DESC,
                method='get', data=data,
                additional_succ_codes={404: TISCALE_MSG_REPORT_PENDING})

            if (phantom.is_fail(ret_val)):
                return (action_result.get_status(), None)

            if (response['processed'] is None):
                time.sleep(TISCALE_SLEEP_SECS)
                continue

            if (phantom.is_success(ret_val)):
                # Add a data dictionary into the result to store information
                hash_data = action_result.add_data({'tiscale_report': response})

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

    def _get_report(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        task_id = param[TISCALE_JSON_TASK_ID]

        # Now poll for the result
        ret_val, response = self._poll_task_status(task_id, action_result)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        data = action_result.add_data({})

        # The next part is the report
        data.update(response)

        malware = data.get('file_info', {}).get('malware', 'no')

        action_result.update_summary({TISCALE_JSON_MALWARE: malware})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _save_file_to_vault(self, action_result, response, sample_hash):

        # Create a tmp directory on the vault partition
        guid = uuid.uuid4()
        local_dir = '/vault/tmp/{}'.format(guid)
        self.save_progress("Using temp directory: {0}".format(guid))

        try:
            os.makedirs(local_dir)
        except Exception as e:
            return action_result.set_status(
                phantom.APP_ERROR,
                "Unable to create temporary folder '/vault/tmp'.", e)

        file_path = "{0}/{1}".format(local_dir, sample_hash)

        # open and download the file
        with open(file_path, 'wb') as f:
            f.write(response.content)

        contains = []
        file_ext = ''
        magic_str = magic.from_file(file_path)
        for regex, cur_contains, extension in self.MAGIC_FORMATS:
            if regex.match(magic_str):
                contains.extend(cur_contains)
                if (not file_ext):
                    file_ext = extension

        file_name = '{}{}'.format(sample_hash, file_ext)

        # move the file to the vault
        vault_ret_dict = Vault.add_attachment(
            file_path, self.get_container_id(),
            file_name=file_name, metadata={'contains': contains})
        curr_data = {}

        if (vault_ret_dict['succeeded']):
            curr_data[phantom.APP_JSON_VAULT_ID] = vault_ret_dict[phantom.APP_JSON_HASH]
            curr_data[phantom.APP_JSON_NAME] = file_name
            action_result.add_data(curr_data)
            wanted_keys = [phantom.APP_JSON_VAULT_ID, phantom.APP_JSON_NAME]
            summary = {x: curr_data[x] for x in wanted_keys}
            if (contains):
                summary.update({'file_type': ','.join(contains)})
            action_result.update_summary(summary)
            action_result.set_status(phantom.APP_SUCCESS)
        else:
            action_result.set_status(
                phantom.APP_ERROR,
                phantom.APP_ERR_FILE_ADD_TO_VAULT)
            action_result.append_to_message(vault_ret_dict['message'])

        # remove the /tmp/<> temporary directory
        shutil.rmtree(local_dir)

        return action_result.get_status()

    def _get_sample(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        sample_hash = param[TISCALE_JSON_HASH]

        self.save_progress('Getting file from TISCALE')

        ret_val, response = self._make_rest_call(
            '/get/sample', action_result, self.GET_SAMPLE_ERROR_DESC,
            method='post', data={'hash': sample_hash},
            parse_response=False)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        return self._save_file_to_vault(action_result, response, sample_hash)

    def _get_platform_id(self, param):

        platform = param.get(TISCALE_JSON_PLATFORM)

        if (not platform):
            return None

        platform = platform.upper()

        if (platform not in self.PLATFORM_ID_MAPPING):
            return None

        return self.PLATFORM_ID_MAPPING[platform]

    def _get_pcap(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        sample_hash = param[TISCALE_JSON_HASH]
        rest_data = {'hash': sample_hash}

        platform_id = self._get_platform_id(param)

        if (platform_id):
            rest_data.update({'platform': platform_id})

        self.save_progress('Getting pcap from TISCALE')

        ret_val, response = self._make_rest_call(
            '/get/pcap', action_result, self.GET_PCAP_ERROR_DESC, method='post',
            data=rest_data, parse_response=False)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        return self._save_file_to_vault(action_result, response, sample_hash)

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

    def _detonate_url(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        # add an http if not present
        url = param[TISCALE_JSON_URL]

        self.save_progress('Detonating URL')

        ret_val, response = self._make_rest_call(
            '/submit/link', action_result, self.FILE_UPLOAD_ERROR_DESC,
            method='post', files={'link': ('', url)})

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        data = action_result.add_data({})

        # The first part is the uploaded file info
        data.update(response)

        # get the sha256
        task_id = response.get('submit-link-info', {}).get('sha256')

        # Now poll for the result
        ret_val, response = self._poll_task_status(task_id, action_result)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # The next part is the report
        data.update(response)

        malware = data.get('file_info', {}).get('malware', 'no')

        action_result.update_summary({TISCALE_JSON_MALWARE: malware})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_vault_file_sha256(self, vault_id, action_result):

        self.save_progress('Getting the sha256 of the file')

        sha256 = None
        metadata = None

        if (hasattr(Vault, 'get_file_info')):
            try:
                metadata = Vault.get_file_info(
                    container_id=self.get_container_id(),
                    vault_id=vault_id)[0]['metadata']
            except Exception as e:
                self.debug_print('Handled Exception:', e)
                metadata = None
        else:
            try:
                metadata = Vault.get_meta_by_hash(
                    self.get_container_id(),
                    vault_id, calculate=True)[0]
            except BaseException:
                self.debug_print('Handled Exception:', e)
                metadata = None

        if (not metadata):
            return (
                action_result.set_status(
                    phantom.APP_ERROR,
                    "Unable to get meta info of vault file"),
                None)

        try:
            sha256 = metadata['sha256']
        except Exception as e:
            self.debug_print('Handled exception', e)
            return (
                action_result.set_status(
                    phantom.APP_ERROR,
                    "Unable to get meta info of vault file"),
                None)

        return (phantom.APP_SUCCESS, sha256)

    def _detonate_file(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, files = self._get_file_dict(param, action_result)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # get the sha256 of the file
        vault_id = param['vault_id']
        ret_val, sha256 = self._get_vault_file_sha256(vault_id, action_result)

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
        # import pdb;pdb.set_trace()

        # Now poll for the result
        ret_val, response = self._poll_task_status(task_id, action_result)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # Add the report
        data.update(response)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_samples(self, action_result, samples):
        # import pdb;pdb.set_trace()
        if (not samples):
            return

        for sample in samples['tc_report']:

            if (not sample):
                continue

            try:
                # Get the data dictionary into the result to store information
                hash_data = action_result.get_data()[0]
                hash_data.update(sample)
            except BaseException:
                print "_handle_samples: Exception adding sample " + str(sample) + "\n ----------------------------------------------"
                continue

            # Update the data with what we got
            print "_handle_samples: " + str(sample) + "\n ----------------------------------------------"
            try:
                positives = sample['classification']['classification']
                if(positives == 0):
                    status = 'UNKNOWN'
                elif(positives == 1):
                    status = 'KNOWN'
                elif(positives == 2):
                    status = 'SUSPICIOUS'
                else:
                    status = 'MALICIOUS'
                # Update the summary
                action_result.update_summary({'classification': status})
            except BaseException:
                action_result.update_summary({'classification': 'UNKOWN'})
                continue

        return

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS
        # Get the action that we are supposed to execute for this connector run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if (action_id == self.ACTION_ID_DETONATE_FILE):
            ret_val = self._detonate_file(param)
        elif (action_id == self.ACTION_ID_DETONATE_URL):
            ret_val = self._detonate_url(param)
        elif (action_id == self.ACTION_ID_GET_REPORT):
            ret_val = self._get_report(param)
        elif (action_id == self.ACTION_ID_GET_SAMPLE):
            ret_val = self._get_sample(param)
        elif (action_id == self.ACTION_ID_GET_PCAP):
            ret_val = self._get_pcap(param)
        elif (action_id == self.ACTION_ID_TEST_ASSET_CONNECTIVITY):
            ret_val = self._test_connectivity(param)
        return ret_val


if __name__ == '__main__':

    import sys

    if (len(sys.argv) < 2):
        print "No test json specified as input"
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = TISCALEConnector()
        connector.print_progress_message = True
        injson = json.dumps(in_json)
        ret_val = connector._handle_action(injson, None)
        print json.dumps(json.loads(ret_val), indent=4)

    exit(0)
