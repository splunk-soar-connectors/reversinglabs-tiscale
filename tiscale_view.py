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

# import json

from tiscale_consts import *


def json_dump_view(provides, all_app_runs, context):

    context['jsons'] = [json.dumps(item, separators=(',', ':'), sort_keys=True, indent=4) for item in j]
    context['jsons'] = jsons = []
    for summary, action_results in all_app_runs:
        jsons.extend([x.id for x in action_results])
    return 'json_dump.html'


def all_results(provides, all_app_runs, context):

    context['menu'] = menu = {}

    # Loop through all the app runs
    for summary, action_results in all_app_runs:
        for result in action_results:
            param = result.get_param()
            target = param.get('hash')
            if (not target):
                target = param.get('vault_id')
            if (not target):
                target = param.get('id')
            menu[target] = {}

    return '/widgets/uber_widget.html'


def parse_report(report):

    # the HTTP connections
    try:
        http_connections = report['network']['url']
    except:
        http_connections = []

    for http_conn in http_connections:

        host = http_conn.get('@host', '')
        if (host):
            if (not host.endswith('/')):
                host += '/'
            if ('://' not in host):
                host = 'http://{0}'.format(host)

        uri = http_conn.get('@uri', '')
        if (uri):
            if (not uri.startswith('/')):
                uri = '/{}'.format(uri)

        url = "{0}/{1}".format(host, uri)
        url = url.replace('///', '/')
        http_conn['url'] = url

    return report


def get_ctx_result(result):

    ctx_result = {}
    param = result.get_param()

    ctx_result['task_id'] = param.get('id')
    ctx_result['vault_id'] = param.get('vault_id')
    ctx_result['vault_file_name'] = param.get('file_name')

    data = result.get_data()

    if (not data):
        return ctx_result

    data = data[0]

    if (not data):
        return ctx_result

    if ('file_info' in data):
        ctx_result['file_info'] = data['file_info']
    elif('upload-file-info' in data):
        ctx_result['file_info'] = data['upload-file-info']

    ctx_result['reports'] = []

    message = result.get_message()

    if (message) and ('max polling attempts' in message):
        ctx_result['message'] = message
        print message

    reports = data.get('task_info', {}).get('report')

    if (not reports):
        return ctx_result

    ctx_result['reports'] = reports
    static_analysis = 1
    dynamic_analysis = 1
    for report in reports:
        software = report.get('software')
        if (not software):
            software = "Not specified, probably running Win XP SP2"
            report['software'] = software

        if ("Static Analyzer" in software):
            report['type'] = 'static'
            report['name'] = 'Static Analysis {}'.format(static_analysis)
            static_analysis += 1
        else:
            report['type'] = 'dynamic'
            report['name'] = 'Dynamic Analysis {}'.format(dynamic_analysis)
            dynamic_analysis += 1

        parse_report(report)

    return ctx_result


def display_report(provides, all_app_runs, context):

    context['results'] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:

            ctx_result = get_ctx_result(result)
            if (not ctx_result):
                continue
            results.append(ctx_result)
    print context
    return 'json_dump.html'
