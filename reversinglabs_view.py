# --
# File: ./reversinglabs/reversinglabs_view.py
#
# Copyright (c) ReversingLabs Inc 2016-2018
#
# This unpublished material is proprietary to ReversingLabs Inc.
# All rights reserved.
# Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of ReversingLabs Inc.
#
# --


def hunting_visualization(provides, all_results, context):

    results = []
    parameters = {}
    for summary, action_results in all_results:
        if not summary or not action_results:
            continue

        for action_result in action_results:

            data = action_result.get_data()
            if not data:
                continue

            for item in data:
                readable_summary = item.get('readable_summary')
                cloud_hunting = item.get('cloud_hunting')
                local_hunting = item.get('local_hunting')
                if readable_summary:
                    parameters['readable_summary'] = readable_summary

                if cloud_hunting:
                    complete, unresolved, status = organise_data_for_frontend(cloud_hunting)

                    parameters['cloud_complete']        = complete
                    parameters['cloud_unresolved']      = unresolved
                    parameters['cloud_unresolved_name'] = status

                if local_hunting:
                    complete, unresolved, status = organise_data_for_frontend(local_hunting)

                    parameters['local_complete']        = complete
                    parameters['local_unresolved']      = unresolved
                    parameters['local_unresolved_name'] = status

    classification = parameters['readable_summary']['classification']['classification']
    parameters['readable_summary']['classification']['classification'] = classification.upper()
    description = parameters['readable_summary']['classification']['description']
    parameters['readable_summary']['classification']['description'] = description.title()
    parameters['readable_summary']['attack'] = parameters['readable_summary']['att&ck']

    for index in range(len(parameters['readable_summary']['attack'])):
        parameters['readable_summary']['attack'][index]['first'] = index == 0
        parameters['readable_summary']['attack'][index]['index'] = str(index)

    for hunting_key, parameters_key in [('cloud_hunting', 'reordered_cloud_hunting'),
                                        ('local_hunting', 'reordered_local_hunting')]:
        if parameters['readable_summary'][hunting_key]:
            parameters['readable_summary'][parameters_key] = _get_hunting_execution_stats(parameters['readable_summary'][hunting_key])

    context['parameters'] = parameters
    context['results'] = results
    context['title_text_color'] = 'white'
    context['body_color'] = '#0F75BC'
    context['title_color'] = 'white'
    return 'reversinglabs_template.html'


def organise_data_for_frontend(cloud_hunting):
    complete   = {}
    unresolved = {}
    status = 'Unresolved'

    for element in cloud_hunting:
        query = element.get('query')
        if not query:
            continue

        query_status = query.get('status')
        if query_status == 'pending' or query_status == 'skipped':
            query_collection = unresolved
            status = query_status.title()

        elif query_status == 'completed':
            query_collection        = complete
            query['malicious']      = element.get('malicious')
            query['description']    = element.get('description').title()
            query['classification'] = element.get('classification').upper()

        else:
            continue

        query_type = query.get('type')
        if query_type == 'search (informative)':
            query_type = 'search_informative'

        data = query_collection.get(query_type)
        if data:
            query_terms = data.get('query_terms')
            if len(query_terms) == 5:
                continue
            query_terms.append(query)
            data['query_terms'] = query_terms

        else:
            readable_type = ' '.join(query_type.split('_')).title()
            query_collection[query_type] = {
                'query_type' : readable_type,
                'query_id'   : query_type,
                'query_terms': [query]
            }

    return complete.values(), unresolved.values(), status


def _get_hunting_execution_stats(hunting_meta_stats):
    stats_fields = {
        "pending"   : [],
        "skipped"   : [],
        "completed" : [],
        "failed"    : [],
        "categories": [],
    }

    for category, values in hunting_meta_stats.iteritems():
        readable_category = ' '.join(category.split('_'))
        stats_fields['categories'].append(readable_category)
        for key, value in values.items():
            stats_fields[key].append(value)

    return stats_fields
