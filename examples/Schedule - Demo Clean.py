"""
This playbook demonstrates a playbook that passes every CI rule.
"""

import phantom.rules as phantom
import json


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    lookup_container_owner(container=container)

    return


@phantom.playbook_block()
def lookup_container_owner(action=None, success=None, container=None, results=None,
                           handle=None, filtered_artifacts=None, filtered_results=None,
                           custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("lookup_container_owner() called")

    parameters = [{"container_id": container.get('id')}]

    phantom.custom_function(
        custom_function="soar-content/cs_lookup_owner",
        parameters=parameters,
        name="lookup_container_owner")

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")
    return
