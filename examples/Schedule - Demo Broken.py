"""
Playbook that violates the CI rules on purpose.
"""

import phantom.rules as phantom
import json

# Deliberately planted for the demo. This is not a real credential.
api_key = "EXAMPLE_NOT_A_REAL_KEY_abcdef1234567890"


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    code_1(container=container)

    return


@phantom.playbook_block()
def code_1(action=None, success=None, container=None, results=None, handle=None,
           filtered_artifacts=None, filtered_results=None, custom_function=None,
           loop_state_json=None, **kwargs):
    phantom.debug("code_1() called")

    parameters = [{"container_id": container.get('id')}]

    phantom.custom_function(
        custom_function="local/cs_lookup_owner",
        parameters=parameters,
        name="cs_lookup_owner")

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")
    return
