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

from phantom.json_keys import *


def file_reputation(provides, all_results, context):

    print "reversinglabs_view: file_reputation " + str(all_results)
    results = []
    parameters = {}
    i = 0
    status_dict = {0: 'Unknown', 1: 'Known', 2: 'Suspicious', 3: 'Malicious'}
    str_class = ['Unknown', 'Known', 'Suspicious', 'Malicious']
    short_report = {}
    # report[0]['data'][0]['task_info']['report'][0]['classification']
    for summary, action_results in all_results:
        print "summary " + str(summary) + " action_results " + str(action_results)
        if not summary or not action_results:
            continue
        for result in action_results:
            parameter = result.get_param()
            result_summary = result.get_summary()

            print "result " + str(result_summary) + " parameter " + str(parameter)
            for dataelem in result.get_data():
                if 'tiscale_report' in dataelem:
                    for tc_report in dataelem['tiscale_report']['tc_report']:
                        results.append(tc_report)

    context['parameters'] = parameters
    context['results'] = results
    context['title_text_color'] = 'white'
    context['body_color'] = '#0F75BC'
    context['title_color'] = 'white'
    return 'reversinglabs_template.html'
