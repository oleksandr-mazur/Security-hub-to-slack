import os
import datetime
import requests


webhook_url = os.environ['webHookUrl']
slack_channel = os.environ['slackChannel']
project_name = os.environ['projectName']
consoleUrl = "https://console.aws.amazon.com/securityhub"

accounts = {
  "111222333444": "A friendly Name"
}


def process_event(event):
    attachment = []

    for finding in event['detail']['findings']:
        if finding['Workflow']['Status'] != "NEW":
            continue
        findingDescription = finding['Description']
        findingTime = finding['UpdatedAt']
        findingTimeEpoch = round(datetime.datetime.strptime(finding['UpdatedAt'], '%Y-%m-%dT%H:%M:%S.%fZ').timestamp())
        account = f"{project_name} ({finding['AwsAccountId']})"
        region = ", ".join(set([res['Region'] for res in finding['Resources']]))
        _type = ", ".join(set([res['Type'] for res in finding['Resources']]))
        messageId = ", ".join(set([res['Id'] for res in finding['Resources']]))
        lastSeen = f"<!date^{findingTimeEpoch}^{{date}} at {{time}} | {findingTime}>"

        color = '#7CD197'
        severity = ''

        if 1 <= finding['Severity']['Normalized'] and finding['Severity']['Normalized'] <= 39: severity, color = 'LOW', '#879596'
        elif 40 <= finding['Severity']['Normalized'] and finding['Severity']['Normalized'] <= 69: severity, color = 'MEDIUM', '#ed7211'
        elif 70 <= finding['Severity']['Normalized'] and finding['Severity']['Normalized'] <= 89: severity, color = 'HIGH', '#ed7211'
        elif 90 <= finding['Severity']['Normalized'] and finding['Severity']['Normalized'] <= 100: severity, color = 'CRITICAL', '#ff0209'
        else: severity, color = 'INFORMATIONAL', '#007cbc'

        attachment.append({
            "fallback": f"{finding} - {consoleUrl}/home?region={region}#/findings?search=id%3D{messageId}",
            "pretext": f"*AWS SecurityHub finding in {region} for Acc: {account}*",
            "title": finding['Title'],
            "title_link": f"{consoleUrl}/home?region={region}#/findings?search=id%3D{messageId}",

            "text": findingDescription,
            "fields": [
                { "title": "Severity", "value": severity, "short": True },
                { "title": "Region", "value": region, "short": True },
                { "title": "Resource Type", "value": _type, "short": True },
                { "title": "Last Seen", "value": lastSeen, "short": True }
            ],
            "mrkdwn_in": ["pretext"],
            "color": color
        })

    if not attachment:
        return

    req = requests.post(webhook_url, json={
        'channel': slack_channel,
        'text': '',
        'attachments': attachment,
        'username': 'SecurityHub',
        'mrkdwn': True,
    })
    print(req.json)
    req.raise_for_status()


def handler(event, context):
    print(event)
    process_event(event)
