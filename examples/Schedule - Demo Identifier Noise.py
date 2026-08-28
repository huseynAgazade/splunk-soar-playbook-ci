"""
This playbook is full of identifier-shaped strings and contains no credentials.
"""

import phantom.rules as phantom
import json

MATTERMOST_CHANNEL_ID = "abc123def456ghi789jkl012mn"
COMMIT_HASH = "1dde526dcfa1051f9af31180b6262d46dd53d040"
NODE_ID = "b3f8a1c2-9d44-4e17-8a56-2f0c1e7d9b34"


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    collect_indicators(container=container)

    return


@phantom.playbook_block()
def collect_indicators(action=None, success=None, container=None, results=None,
                       handle=None, filtered_artifacts=None, filtered_results=None,
                       custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("collect_indicators() called")

    parameters = [{
        "container_id": container.get('id'),
        "artifact_id": 88214,
        "playbook_id": "soar-content/Input - Indicator Handler",
        "condition_key": "condition_key_f82a1f36-2b25-4427-a1a8-57fc55ea5b47",
        "comparison_key": "comparison_key_0a9d77e1-4c3b-41aa-9f2e-6b1d84c5e903",
        "file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "node_id": NODE_ID,
        "commit_hash": COMMIT_HASH,
        "channel_id": MATTERMOST_CHANNEL_ID,
        "session_reference": "cGxheWJvb2stcnVuLXJlZmVyZW5jZS1ub3QtYS1zZWNyZXQ=",
    }]

    phantom.custom_function(
        custom_function="soar-content/cs_collect_indicators",
        parameters=parameters,
        name="collect_indicators")

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")
    return
