import sys
import os
sys.path.insert(0,
    os.path.join(
        os.path.dirname(
            os.path.dirname(os.path.abspath(__file__))), "src"))

import unittest
import iamutils
import boto3
from botocore.exceptions import ClientError

# python -m unittest iamutils_test.TestIamUtils


class TestIamUtils(unittest.TestCase):
    def setUp(self):
        self.test_iam_group_name = 'iamtool_testgroup'
        self.test_iam_policy_name = 'iamtool_testpolicy'
        self.test_iam_user_name = 'iamtool_testuser'
        self.setup_environment_variables()
        self.setup_create_test_group()
        self.setup_create_custom_policy()
        self.setup_attach_test_group_policies()
        self.setup_create_test_user()

    def tearDown(self):
        self.teardown_detach_test_group_policies()
        self.teardown_delete_test_group()
        self.teardown_delete_custom_policy()
        self.teardown_delete_test_user()

    def setup_environment_variables(self):
        if not os.environ.get('AWS_DEFAULT_REGION', None):
            os.environ['AWS_DEFAULT_REGION'] = 'us-east-1'
        if not os.environ.get('IAMTOOL_DYNAMODB_CONFIG_TABLE_NAME', None):
            os.environ['IAMTOOL_DYNAMODB_CONFIG_TABLE_NAME'] = 'iamusertool_config'

    def setup_create_test_group(self):
        client = boto3.client('iam')
        exists = True
        try:
            response = client.get_group(GroupName=self.test_iam_group_name)
        except client.exceptions.NoSuchEntityException as e:
            exists = False
        if not exists:
            response = client.create_group(
                Path='/',
                GroupName=self.test_iam_group_name
            )

    def teardown_delete_test_group(self):
        client = boto3.client('iam')
        exists = True
        try:
            response = client.get_group(GroupName=self.test_iam_group_name)
        except client.exceptions.NoSuchEntityException as e:
            exists = False
        if exists:
            response = client.delete_group(GroupName=self.test_iam_group_name)

    def setup_attach_test_group_policies(self):
        iam = boto3.resource('iam')
        group = iam.Group(self.test_iam_group_name)
        _ = group.attach_policy(
            PolicyArn='arn:aws:iam::aws:policy/AmazonPollyReadOnlyAccess')
        _ = group.attach_policy(
            PolicyArn=self.test_iam_policy_arn)

    def teardown_detach_test_group_policies(self):
        iam = boto3.resource('iam')
        group = iam.Group(self.test_iam_group_name)
        _ = group.detach_policy(
            PolicyArn='arn:aws:iam::aws:policy/AmazonPollyReadOnlyAccess')
        _ = group.detach_policy(
            PolicyArn=self.test_iam_policy_arn)

    def setup_create_custom_policy(self):
        client = boto3.client('iam')
        # response = client.get_policy(
        #     PolicyArn='string'
        # )
        try:
            response = client.create_policy(
                PolicyName=self.test_iam_policy_name,
                Path='/',
                PolicyDocument=\
"""{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "sts:AssumeRole"
            ],
            "Resource": "arn:aws:iam::123456789012:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
        }
    ]
}
""",
                Description='Temporary use for unit tests for aws-iam-user-tool'
            )
            self.test_iam_policy_arn = response['Policy']['Arn']
        except client.exceptions.EntityAlreadyExistsException as e:
            # if it already exists just return the arn
            self.test_iam_policy_arn = \
                "arn:aws:iam::{}:policy/{}".format(
                    iamutils.get_aws_account_id(),
                    self.test_iam_policy_name)

    def teardown_delete_custom_policy(self):
        client = boto3.client('iam')
        response = client.delete_policy(
            PolicyArn=self.test_iam_policy_arn
        )

    def setup_create_test_user(self):
        client = boto3.client('iam')
        exists = True
        try:
            client.get_user(UserName=self.test_iam_user_name)
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                exists = False
        if not exists:
            response = client.create_user(
                Path='/',
                UserName=self.test_iam_user_name
            )

    def teardown_delete_test_user(self):
        client = boto3.client('iam')
        response = client.delete_user(
            UserName=self.test_iam_user_name
        )

    def test_get_account_id_from_arn(self):
        # example URLs from https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html
        arns_with_account_id = [
            "arn:aws:elasticbeanstalk:us-east-1:123456789012:environment/My App/MyEnvironment",
            "arn:aws:iam::123456789012:user/David",
            "arn:aws:rds:eu-west-1:123456789012:db:mysql-db",
            "arn:aws:cloudfront::123456789012:*"
        ]
        arns_no_id = [
            "arn:aws:s3:::my_corporate_bucket/exampleobject.png",
            "arn:aws:apigateway:us-east-1::/restapis/a123456789012bc3de45678901f23a45/*",
            "arn:aws:ec2:us-east-1::image/ami-1a2b3c4d"
        ]
        for arn in arns_with_account_id:
            self.assertEqual(
                iamutils.get_account_id_from_arn(arn),
                "123456789012"
                )

        for arn in arns_no_id:
            self.assertEqual(
                iamutils.get_account_id_from_arn(arn),
                ""
                )

    def test_get_iam_group_arn(self):
        arn = iamutils.get_iam_group_arn(self.test_iam_group_name)
        self.assertEqual(arn[0:13], "arn:aws:iam::")
        self.assertEqual(arn.split(':')[-1], "group/{}".format(self.test_iam_group_name))
        pass

    def test_infer_env_name(self):
        self.assertEqual('Prod',
            iamutils.infer_env_name('prod-developers'))
        self.assertEqual('Dev',
            iamutils.infer_env_name('dev-developers'))
        self.assertEqual('If-we-cant-tell',
            iamutils.infer_env_name('if-we-cant-tell'))

    def test_get_active_policy_document(self):
        policy_document = iamutils.get_active_policy_document(
            'arn:aws:iam::aws:policy/AdministratorAccess')
        # >>> print(policy_document)
        # {'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Action': '*', 'Resource': '*'}]}
        self.assertEqual("Allow",
            policy_document['Statement'][0]['Effect'])
        self.assertEqual("*",
            policy_document['Statement'][0]['Resource'])

    def test_get_group_attached_policy_arns(self):
        policy_arns = iamutils.get_group_attached_policy_arns(
            self.test_iam_group_name)
        self.assertTrue(
            'arn:aws:iam::aws:policy/AmazonPollyReadOnlyAccess' in policy_arns)

    def test_is_arn_iamrole(self):
        # example URLs from https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html
        arns_not_role = [
            "arn:aws:elasticbeanstalk:us-east-1:123456789012:environment/My App/MyEnvironment",
            "arn:aws:iam::123456789012:user/David",
            "arn:aws:rds:eu-west-1:123456789012:db:mysql-db",
            "arn:aws:cloudfront::123456789012:*"
        ]
        for arn in arns_not_role:
            self.assertFalse(iamutils.is_arn_iamrole(arn))
        self.assertTrue(
            iamutils.is_arn_iamrole("arn:aws:iam::123456789012:role/myrole")
            )

    def test_find_allowed_assume_role_arns(self):
        arns = iamutils.find_allowed_assume_role_arns(
            self.test_iam_policy_arn)
        self.assertTrue(
            "arn:aws:iam::123456789012:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling" \
            in arns
            )

    def test_get_iam_group_cross_account_role_arns(self):
        cross_account_arns = iamutils.get_iam_group_cross_account_role_arns(
            self.test_iam_group_name)
        self.assertTrue(
            "arn:aws:iam::123456789012:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling" \
            in cross_account_arns
            )

    def test_user_exists(self):
        self.assertTrue(iamutils.user_exists(self.test_iam_user_name))
        self.assertFalse(iamutils.user_exists("not_a_valid_username"))

    def test_email_config(self):
        iamutils.set_email_config(
            email_from='devops@mycompany.com',
            email_replyto='noreply@mycompany.com',
            email_bcc ='someinterestedparty@mycompany.com',
            id='EMAIL_CONFIG_UNITTEST'
            )
        config = iamutils.get_email_config(id='EMAIL_CONFIG_UNITTEST')
        self.assertEqual(config['email_from_address'], 'devops@mycompany.com')
        self.assertEqual(config['email_replyto_address'], 'noreply@mycompany.com')
        self.assertEqual(config['email_bcc_address'], 'someinterestedparty@mycompany.com')
