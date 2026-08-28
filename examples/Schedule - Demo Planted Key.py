"""
This playbook is structurally valid and carries a planted credential.
"""

import phantom.rules as phantom
import json

# Deliberately planted so the secret scan has something to find.
# This is NOT a real credential.
api_key = "EXAMPLE_NOT_A_REAL_KEY_abcdef1234567890"


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

    parameters = [{"container_id": container.get('id'), "api_key": api_key}]

    phantom.custom_function(
        custom_function="soar-content/cs_lookup_owner",
        parameters=parameters,
        name="lookup_container_owner")

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")
    return
