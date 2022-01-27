# File: tiscale_consts.py
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

TISCALE_JSON_BASE_URL = "base_url"
TISCALE_JSON_API_KEY = "api_key"  # pragma: allowlist secret
TISCALE_JSON_MALWARE = "malware"
TISCALE_JSON_TASK_ID = "id"
TISCALE_JSON_VAULT_ID = "file_vault_id"
TISCALE_JSON_URL = "url"
TISCALE_JSON_HASH = "hash"
TISCALE_JSON_PLATFORM = "platform"
TISCALE_JSON_POLL_TIMEOUT_MINS = "timeout"
TISCALE_JSON_HUNTING_META = 'hunting_meta'
TISCALE_JSON_HUNTING_STATE = 'hunting_report_vault_id'

TISCALE_ERR_UNABLE_TO_PARSE_REPLY = "Unable to parse reply from device"
TISCALE_ERR_REPLY_FORMAT_KEY_MISSING = "None '{key}' missing in reply from device"
TISCALE_ERR_REPLY_NOT_SUCCESS = "REST call returned '{status}'"
TISCALE_SUCC_REST_CALL_SUCCEEDED = "REST Api call succeeded"
TISCALE_ERR_REST_API = "REST Api Call returned error, status_code: {status_code}, detail: {detail}"

TISCALE_TEST_PDF_FILE = "tiscale_test_connectivity.pdf"
TISCALE_SLEEP_SECS = 10
TISCALE_MSG_REPORT_PENDING = "Report Pending"
TISCALE_MSG_MAX_POLLS_REACHED = "Reached max polling attempts." \
    "Please use the MD5 or Sha256 of the file as a parameter to <b>get report</b> to query the report status."

# in minutes
TISCALE_MAX_TIMEOUT_DEF = 10
