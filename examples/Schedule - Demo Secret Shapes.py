"""
This playbook carries several fabricated credential shapes for scanner testing.
"""

import phantom.rules as phantom
import json

# --- all fabricated, none of these authenticate anywhere ---------------------
AWS_ACCESS_KEY = "AKIAFAKEKEYNOTREAL00"
SLACK_WEBHOOK_TOKEN = "xoxb-000000000000-FAKE-NOT-A-REAL-TOKEN"
SERVICE_PASSWORD = "Sup3rSecretFakePassw0rd"
BEARER_HEADER = "Bearer FAKEfakeFAKEfakeFAKEfakeFAKEfake00"
SESSION_JWT = (
    "ey" + "JhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".ey" + "JzdWIiOiJmYWtlIiwibmFtZSI6InRlc3QifQ"
    ".FAKEsignatureNOTREALvalue0000000000"
)


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    push_to_downstream(container=container)

    return


@phantom.playbook_block()
def push_to_downstream(action=None, success=None, container=None, results=None,
                       handle=None, filtered_artifacts=None, filtered_results=None,
                       custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("push_to_downstream() called")

    # A secret reached indirectly, with nothing secret-shaped on this line.
    headers = {"Authorization": BEARER_HEADER}

    parameters = [{
        "container_id": container.get('id'),
        "channel_id": "abc123def456ghi789jkl012mn",
        "headers": headers,
        "aws_key": AWS_ACCESS_KEY,
    }]

    phantom.custom_function(
        custom_function="soar-content/cs_push_downstream",
        parameters=parameters,
        name="push_to_downstream")

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")
    return
