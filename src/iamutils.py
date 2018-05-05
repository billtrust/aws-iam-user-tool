import os
import base64
import hashlib
import json
import boto3
import privnote
from botocore.exceptions import ClientError
from boto3 import resource

import logging
logging.basicConfig(level=os.environ.get("APP_LOGLEVEL", "INFO"))
logger = logging.getLogger(__name__)


def get_aws_account_id():
    return boto3.client('sts').get_caller_identity()['Account']


def ensure_envvars():
    """Ensure that these environment variables are provided at runtime"""
    required_envvars = [
        "AWS_DEFAULT_REGION",
        "IAMTOOL_DYNAMODB_CONFIG_TABLE_NAME",
        "IAMTOOL_SES_TEMPLATE_NAME"
    ]

    missing_envvars = []
    for required_envvar in required_envvars:
        if not os.environ.get(required_envvar, ''):
            missing_envvars.append(required_envvar)
    
    if missing_envvars:
        message = "Required environment variables are missing: " + \
            repr(missing_envvars)
        logger.error(message)
        raise AssertionError(message)


def user_exists(user_name):
    client = boto3.client('iam')
    try:
        client.get_user(UserName=user_name)
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            return False
        else:
            logger.error("Unexpected error from IAM get_user:", e)
            raise
    except Exception as e:
        logger.error("Unexpected error from IAM get_user:", e)
        raise
    return True


def provision_user(user_name, group_names, user_email, ses_email_template_name):
    email_config = get_email_config()
    validate_iam_group_names(group_names)

    # create user and assign groups
    temppw = generate_temp_password(16)
    privnote_url = privnote.generate_privnote_url(temppw)
    create_iam_user(user_name, temppw)
    add_user_to_groups(user_name, group_names)

    # get metadata for email
    password_policy = get_password_policy()
    cross_account_groups = get_cross_account_role_groupings(group_names)
    console_login_url = get_console_login_url()
    props = generate_email_template_data(
        user_name,
        privnote_url,
        password_policy,
        cross_account_groups,
        console_login_url)

    # send the email
    send_ses_templated_email(
        ses_template_name=ses_email_template_name,
        email_to=user_email,
        email_bcc=email_config['email_bcc_address'] if 'email_bcc_address' in email_config else None,
        email_from=email_config['email_from_address'],
        email_replyto=email_config['email_replyto_address'],
        template_data=json.dumps(props)
    )


def set_email_config(email_from, email_replyto, email_bcc=None, id='EMAIL_CONFIG'):
    item = {
        'id': id,
        'email_from_address': email_from,
        'email_replyto_address': email_replyto,
    }
    if email_bcc:
        item['email_bcc_address'] = email_bcc

    logger.info("Setting email configuration to DynamoDB...")
    boto3.setup_default_session(region_name=os.environ['AWS_DEFAULT_REGION'])
    dynamodb_resource = resource('dynamodb')
    table = dynamodb_resource.Table(os.environ['IAMTOOL_DYNAMODB_CONFIG_TABLE_NAME'])
    _ = table.put_item(Item=item)


def get_email_config(id='EMAIL_CONFIG'):
    logger.info("Retrieving email configuration from DynamoDB...")
    boto3.setup_default_session(region_name=os.environ['AWS_DEFAULT_REGION'])
    dynamodb_resource = resource('dynamodb')
    table_name = os.environ['IAMTOOL_DYNAMODB_CONFIG_TABLE_NAME']
    table = dynamodb_resource.Table(table_name)
    response = table.get_item(Key={'id': id})
    if not 'Item' in response:
        raise Exception(f"Could not read config from DynamoDB table {table_name}, id(key): {id}")
    return response['Item']


def generate_email_template_data(
        user_name, privnote_url, password_policy, cross_account_groups, console_login_url):
    props = {
        "aws_console_login_url": console_login_url,
        "iam_username": user_name,
        "pw": privnote_url,
        "pw_policy": {
            "MinimumPasswordLength": password_policy['MinimumPasswordLength'],
            "RequireSymbols": password_policy['RequireSymbols'],
            "RequireNumbers": password_policy['RequireNumbers'],
            "RequireUppercaseCharacters": password_policy['RequireUppercaseCharacters'],
            "RequireLowercaseCharacters": password_policy['RequireLowercaseCharacters']
        },
        "roles": cross_account_groups
    }
    logger.debug("Email template data: " + str(props))
    return props


def validate_iam_group_names(group_names):
    """Since the IAM group names are passed into the CLI as
    arguments, this will validate them to ensure that these
    group names exist and were typed correctly."""
    client = boto3.client('iam')
    for group_name in group_names:
        logger.info(f"Validating IAM group {group_name}")
        try:
            response = client.get_group(
                GroupName=group_name
            )
        except Exception as e:
            message = f"Invalid IAM Group specified: {group_name}"
            logger.error(message)
            raise AssertionError(message)


def add_user_to_groups(user_name, group_names):
    client = boto3.client('iam')
    for group_name in group_names:
        logger.info(f"Adding {user_name} to group {group_name}")
        response = client.add_user_to_group(
            GroupName=group_name,
            UserName=user_name,
        )


def generate_temp_password(num_characters):
    pw = base64.urlsafe_b64encode(
        hashlib.md5(os.urandom(128)).digest()
    )[:num_characters]
    # make sure it meets the account password policy
    return f"A{pw}9!"


def create_iam_user(user_name, temppw):
    client = boto3.client('iam')
    logger.info(f"Creating user {user_name}")
    response = client.create_user(
        Path='/',
        UserName=user_name
    )
    logger.info(f"Creating login profile for user {user_name}")
    response = client.create_login_profile(
        UserName=user_name,
        Password=str(temppw),
        PasswordResetRequired=True
    )


def get_iam_group_arn(group_name):
    """Get a full iam group arn from just the group name"""
    client = boto3.client('iam')
    return client.get_group(GroupName=group_name)['Group']['Arn']


def get_account_id_from_arn(arn):
    if not type(arn) is str:
        raise Exception("Non string passed to get_account_id_from_arn")
    return arn.split(':')[4]


def build_switch_role_url(assume_role_arn, display_name):
    role_name = assume_role_arn.split(':')[5].replace('role/', '')
    url = "https://signin.aws.amazon.com/switchrole"
    url += f"?account={get_account_id_from_arn(assume_role_arn)}"
    url += f"&roleName={role_name}"
    url += f"&displayName={display_name}"
    return url


def get_group_attached_policy_arns(group_name):
    """Get all policy arns which are attached to the given group"""
    policy_arns = []
    client = boto3.client('iam')
    response = client.list_attached_group_policies(
        GroupName=group_name,
        MaxItems=100
    )
    for policy in response['AttachedPolicies']:
        policy_arns.append(policy['PolicyArn'])
    while response['IsTruncated'] == True:
        marker = response['Marker']
        response = client.list_attached_group_policies(
            GroupName=group_name,
            MaxItems=100,
            Marker=marker
        )
        for policy in response['AttachedPolicies']:
            policy_arns.append(policy['PolicyArn'])
    return policy_arns        


def get_active_policy_document(policy_arn):
    """Returns the policy (Dict) for the given policy arn"""
    client = boto3.client('iam')
    default_version_id = \
        client.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
    policy_document = client.get_policy_version(
        PolicyArn = policy_arn,
        VersionId = default_version_id
    )['PolicyVersion']['Document']
    return policy_document


def is_arn_iamrole(arn):
    """Given an arn, determines if this is an IAM role arn"""
    if not arn.startswith('arn:aws:iam'):
        logger.debug("is not an arn: {}".format(arn))
        return False
    if not arn.split(':')[-1].startswith('role/'):
        return False
    return True


def find_allowed_assume_role_arns(policy_arn):
    """Given an IAM policy, this digs into it to find all
    arns which are granted sts:AssumeRole permission.
    Returns a list of arns."""
    policy_document = get_active_policy_document(policy_arn)
    logger.debug("policy_document:", policy_document)
    assume_role_arns = []
    for statement in policy_document['Statement']:
        if isinstance(statement['Resource'], list):
            arns = statement['Resource']
        else:
            arns = [statement['Resource']]
        for arn in arns:
            if is_arn_iamrole(arn) and \
               statement['Effect'] == 'Allow' and \
               'sts:AssumeRole' in statement['Action']:
                assume_role_arns.append(arn)
    return assume_role_arns if not len(assume_role_arns) == 0 else None


def get_iam_group_cross_account_role_arns(group_name):
    """Given an IAM group name, this will find any cross account IAM roles
    which can be assumed due to membership in this group"""

    # get the account id of the current account
    group_arn = get_iam_group_arn(group_name)
    group_account_id = get_account_id_from_arn(group_arn)

    # get all the role arn's this group is allowed to assume
    assume_role_arns = []
    # get all policies attached to the group
    policy_arns = get_group_attached_policy_arns(group_name)
    logger.debug("policy_arns:", policy_arns)
    # get all roles allowed to be assumed by these policies
    for policy_arn in policy_arns:
        logger.debug("policy_arn:", policy_arn)
        arns = find_allowed_assume_role_arns(policy_arn)
        logger.debug("arns:", arns)
        if arns: assume_role_arns.extend(arns)

    # then build a list of roles which are cross account
    cross_account_role_arns = []
    logger.debug(assume_role_arns)
    for assume_role_arn in assume_role_arns:
        role_account_id = get_account_id_from_arn(assume_role_arn)
        # if the role is in a different account, must be a cross role account
        if role_account_id != group_account_id:
            cross_account_role_arns.append(assume_role_arn)
    return cross_account_role_arns


def get_cross_account_role_groupings(iam_group_names):
    """Return a Dict with all the cross role urls withenvironment name."""
    display_name = get_account_alias()
    cross_account_groups = []
    for group_name in iam_group_names:
        arns = get_iam_group_cross_account_role_arns(group_name)
        for arn in arns:
            # if there are multiple arns in the group, use the role name
            # else use the group name for the display name                
            if len(arns) > 1:
                role_name = arn.split(':')[-1].split('/')[-1]
                display_name = role_name
            else:
                display_name = group_name
            cross_account_groups.append({
                'assume_role_url': build_switch_role_url(arn, display_name),
                'env_name': group_name
                }
            )
    return cross_account_groups


def get_password_policy():
    logger.info("Retrieving account password policy")
    client = boto3.client('iam')
    response = client.get_account_password_policy()
    policy = response['PasswordPolicy']
    return policy


def get_account_alias():
    iam = boto3.client('iam')

    paginator = iam.get_paginator('list_account_aliases')
    try:
        from first import first
        item = first(paginator.paginate(), default=None)
        if not item:
            raise Exception("No AWS account alias exists")
        else:
            if len(item['AccountAliases']) > 1:
                logger.warn("Multiple AWS account aliases found")
            return item['AccountAliases'][0]
    except Exception as e:
        raise Exception("Error retrieving AWS account alias: {}".format(e))


def get_console_login_url():
    return "https://{}.signin.aws.amazon.com/console".format(
        get_account_alias()
    )


def send_ses_templated_email(
        ses_template_name,
        email_to,
        email_bcc,
        email_from,
        email_replyto,
        template_data
    ):
    logger.info(f"Sending {ses_template_name} email to {email_to}")
    destinations = {
        'ToAddresses':  [ email_to ]
    }
    if email_bcc:
        destinations['BccAddresses'] = [ email_bcc ]
    client = boto3.client('ses')
    response = client.send_templated_email(
        Source=email_from,
        Destination=destinations,
        ReplyToAddresses=[ email_replyto ],
        ReturnPath=email_from,
        Template=ses_template_name,
        TemplateArn=f"arn:aws:ses:us-east-1:951954082978:template/{ses_template_name}",
        TemplateData=template_data
    )
