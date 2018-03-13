import boto3
from datetime import datetime
import dateutil.tz
import json
import ast
import os, sys
import botocore
from boto.s3.key import Key
import datetime, requests
from datetime import timedelta
from base64 import b64decode

# AWS Variables
s3r = boto3.resource('s3')
s3 = boto3.client('s3')
kms = boto3.client('kms')

BUCKET_NAME = "newwave-sox-kwjer3209"
mybucket = s3r.Bucket(BUCKET_NAME)

# Static variables
BUILD_VERSION = '0.0.2'
SERVICE_ACCOUNT_NAME = ['']
GROUP_LIST = ["kops","admin_full_mfa","nw-classic-users"]

# Environ
AWS_REGION = 'us-east-1'
AWS_EMAIL_REGION = 'us-east-1'
EMAIL_TO_ADMIN = os.environ["EMAIL_TO_ADMIN"]
EMAIL_FROM = os.environ["EMAIL_FROM"]
EMAIL_SEND_COMPLETION_REPORT = os.environ["EMAIL_SEND_COMPLETION_REPORT"]
TOKEN = kms.decrypt(CiphertextBlob=b64decode(os.environ["TOKEN"]))['Plaintext'] # Loggly token

# Length of mask over the IAM Access Key
MASK_ACCESS_KEY_LENGTH = 16

# First email warning
FIRST_WARNING_NUM_DAYS = 76
FIRST_WARNING_MESSAGE = 'You have 14 days left before your AWS Access key gets disabled'
# Last email warning
LAST_WARNING_NUM_DAYS = 83
LAST_WARNING_MESSAGE = 'You have 7 days left before your AWS Access key gets disabled'

# Max AGE days of key after which it is considered EXPIRED (deactivated)
KEY_MAX_AGE_IN_DAYS = 90
KEY_EXPIRED_MESSAGE = 'Your AWS Access has been disabled'
KEY_YOUNG_MESSAGE = ''

# ==========================================================

# Character length of an IAM Access Key
ACCESS_KEY_LENGTH = 20
KEY_STATE_ACTIVE = "Active"
KEY_STATE_INACTIVE = "Inactive"

# ==========================================================

#check to see if the MASK_ACCESS_KEY_LENGTH has been misconfigured
if MASK_ACCESS_KEY_LENGTH > ACCESS_KEY_LENGTH:
    MASK_ACCESS_KEY_LENGTH = 16

# ==========================================================

HEADER = '''<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
           "http://www.w3.org/TR/html4/strict.dtd">
        <HTML>
           <HEAD>
           </HEAD>
           <BODY>
              <p>Hello<p>'''
FOOTER = "<p>Defcon4</p></BODY></HTML>"

# ==========================================================


def tzutc():
    return dateutil.tz.tzutc()


def key_age(key_created_date):
    tz_info = key_created_date.tzinfo
    age = datetime.datetime.now(tz_info) - key_created_date

    key_age_str = str(age)
    if 'days' not in key_age_str:
        return 0

    days = int(key_age_str.split(',')[0].split(' ')[0])

    return days

# Function upload for the new file to s3 bucket
def putObject(data, key_name):
    Object  = s3r.Object(BUCKET_NAME,key_name)
    Object.put(Body=json.dumps(data), ContentType='application/json', ACL='authenticated-read')

# Send keys desactivation email
def send_deactivate_email(username, age, access_key_id):
    email_to = ['{}@adesa.com'.format(username),'{}@openlane.com'.format(username)]
    client = boto3.client('ses', region_name=AWS_EMAIL_REGION)
    response = client.send_email(
        Source=EMAIL_FROM,
        Destination={
            'ToAddresses': [email_to]
        },
        Message={
            'Subject': {
                'Data': 'AWS IAM Access Key Rotation - Deactivation of Access Key: %s' % access_key_id
            },
            'Body': {
                'Html': {
                'Data': 'The Access Key [%s] belonging to User [%s] has been automatically deactivated due to it being %s days old' % (access_key_id, username, age)
                }
            }
        })
    print(json.dumps({"username":username,"email_to":email_to,"access_key_id":access_key_id,"key_age":age,"subject":"deactivated"}))


# Send summary email to the Admins
def send_completion_email(email_to, finished, report):
    client = boto3.client('ses', region_name=AWS_EMAIL_REGION)
    response = client.send_email(
        Source=EMAIL_FROM,
        Destination={
            'ToAddresses': [email_to]
        },
        Message={
            'Subject': {
                'Data': 'AWS IAM Access Key Rotation - Report'
            },
            'Body': {
                'Html': {
                'Data': '{} </p>AWS IAM Access Key Rotation finished successfully at {}\nDeactivation Report:</p> {} {}'.format(HEADER, finished, report, FOOTER)
                }
            }
        })


# Send warning message to a specific user
def send_warning_email(message, username, age, access_key_id):
    email_to = ['{}@adesa.com'.format(username),'{}@openlane.com'.format(username)]
    client = boto3.client('ses', region_name=AWS_EMAIL_REGION)
    response = client.send_email(
        Source=EMAIL_FROM,
        Destination={
            'ToAddresses': email_to
        },
        Message={
            'Subject': {
                'Data': 'AWS IAM Access Key Rotation - Warning'
            },
            'Body': {
                'Html': {
                'Data': '{} {}'
                        '<p> Access Keys age: {} </p>'
                        '<p>Access key ID: {} </p>'
                        '<p>AWS username: {} </p>'
                        '<p>Command to generate a New AWS Secret Key: <b> aws iam create-access-key --user-name {}</b> </p>'
                        '<p>Command to delete the expired AWS Access key: <b>aws iam delete-access-key --access-key {} --user-name {} </b></p>{}'.format(HEADER,message,age,access_key_id,username,username,access_key_id,username,FOOTER)
                }
            }
        })

    print(json.dumps({"message":message,"email_to":email_to,"access_key_id":access_key_id,"key_age":age,"subject":"warning"}))

def formatReport(report_input):
    report_html = "<tr>"


    for users in report_input["users"]:
        for keys in users["keys"]:
            report_html = report_html  \
                          + " <td> " + users["username"] + " </td> "\
                          + " <td> " + `keys["age"]` + " </td> "\
                          + " <td> " + `keys["changed"]` + " </td> "\
                          + " <td> " + keys["message"] + " </td> "\
                          + " <td> " + keys["accesskeyid"] + " </td> " + "</tr>"


    final_report = "<table>{}</table>".format(report_html)


    return final_report

def mask_access_key(access_key):
    return access_key[-(ACCESS_KEY_LENGTH-MASK_ACCESS_KEY_LENGTH):].rjust(len(access_key), "*")


# Post event to loggly
def postToLoggly(data):
    metric_name = "metrics-sec"
    headers = {'Content-type': 'application/json'}
    r = requests.post("https://logs-01.loggly.com/inputs/{}/tag/metrics-sec/".format(TOKEN,metric_name),data=json.dumps(data),headers=headers)


# Format logging
# def formatLogging(input):
#     formated = ""
#     for row in input:
#         formated = '{}="{}" {}'.format(row, input[row], formated)
#     return formated


def lambda_handler(event, context):
    # print '*****************************'
    # print 'RotateAccessKey (%s): starting...' % BUILD_VERSION
    # print '*****************************'
    # Connect to AWS APIs
    client = boto3.client('iam')

    users = {}
    data = client.list_users()

    userindex = 0

    for user in data['Users']:
        userid = user['UserId']
        username = user['UserName']
        users[userid] = username

    users_report1 = []
    users_report2 = []

    for user in users:
        userindex += 1
        user_keys = []

        username = users[user]

        # test is a user belongs to a specific list of groups. If they do, do not invalidate the access key
        # print "Test if the user belongs to the exclusion group"
        user_groups = client.list_groups_for_user(UserName=username)
        skip = False
        for groupName in user_groups['Groups']:
            if groupName['GroupName'] in GROUP_LIST:
                # print 'Detected that user belongs to ', GROUP_LIST
                skip = True
                continue

        if skip:
            # print "Do invalidate Access Key"
            continue

        # check to see if the current user is a special service account
        if username in SERVICE_ACCOUNT_NAME:
            # print 'detected special service account %s, skipping account...', username
            continue

        access_keys = client.list_access_keys(UserName=username)['AccessKeyMetadata']
        for access_key in access_keys:

            access_key_id = access_key['AccessKeyId']
            masked_access_key_id = mask_access_key(access_key_id)
            existing_key_status = access_key['Status']
            key_created_date = access_key['CreateDate']
            age = key_age(key_created_date)

            key_state = 'active_ok'
            key_message = 'No action required'
            key_warning = False
            key_state_changed = False

            # we only need to examine the currently Active and about to expire keys
            if existing_key_status == "Inactive":
                key_state = "inactive"
                key_message = 'key is already in an INACTIVE state'
                key_info = {'accesskeyid': masked_access_key_id, 'age': age, 'state': key_state, 'changed': False}

            else:
                if age == send_warning_email:
                    key_state = "active_warning"
                    key_message = FIRST_WARNING_MESSAGE
                    key_warning = True
                elif age == LAST_WARNING_NUM_DAYS:
                    key_state = "active_warning"
                    key_message = LAST_WARNING_MESSAGE
                    key_warning = True

                # Send an email to the users
                if key_warning == True:
                    send_warning_email(key_message,username,age,access_key_id)

                # Send Email to the Admins
                if age >= KEY_MAX_AGE_IN_DAYS:
                    key_state = 'active_expired'
                    client.update_access_key(UserName=username, AccessKeyId=access_key_id, Status=KEY_STATE_INACTIVE)
                    send_deactivate_email(username, age, masked_access_key_id)
                    key_state_changed = True
                    key_message = 'AWS Access desactivated for the user'


            key_info = {'accesskeyid': masked_access_key_id, 'age': age, 'message': key_message, 'changed': key_state_changed, 'key_state': key_state}
            user_keys.append(key_info)
            key_complete_info = {"user_info":{'username':username, 'userid':userindex, 'accesskeyid': masked_access_key_id, 'age': age, 'message': key_message, 'changed': key_state_changed, 'key_state': key_state}}
            postToLoggly(key_complete_info)

        user_info_with_username = {'userid': userindex, 'username': username, 'keys': user_keys}
        users_report1.append(user_info_with_username)


    finished = str(datetime.datetime.now())
    deactivated_report = {'reportdate': finished, 'users': users_report1}

    # Sending report
    if EMAIL_SEND_COMPLETION_REPORT:
        # Format report to HTML table
        final_report = formatReport(deactivated_report)
        send_completion_email(EMAIL_TO_ADMIN, finished, final_report)

    return deactivated_report

if __name__ == "__main__":
   event = context = {}
   lambda_handler(event, context)