data "aws_caller_identity" "current" {}

resource "aws_iam_role" "aws-iam-user-tool" {
  name = "role-aws-iam-user-tool"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": [
            "ec2.amazonaws.com",
            "ecs-tasks.amazonaws.com"
            ],
        "AWS": [
            "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        ]
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

resource "aws_iam_policy" "aws-iam-user-tool" {
  name = "policy-aws-iam-user-tool"
  path = "/"

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AccessNeededByApplicationIAM",
            "Action": [
                "iam:CreateUser",
                "iam:CreateLoginProfile",
                "iam:AddUserToGroup",
                "iam:GetGroup",
                "iam:ListAccountAliases",
                "iam:ListAttachedGroupPolicies",
                "iam:GetPolicy",
                "iam:GetPolicyVersion",
                "iam:GetUser"
            ],
            "Effect": "Allow",
            "Resource": "*"
        },
        {
            "Sid": "AccessNeededByApplicationSES",
            "Action": [
                "ses:SendTemplatedEmail"
            ],
            "Effect": "Allow",
            "Resource": "*"
        },
        {
            "Sid": "AccessNeededByApplicationDynamoDB",
            "Action": [
                "dynamodb:PutItem",
                "dynamodb:GetItem"
            ],
            "Effect": "Allow",
            "Resource": "arn:aws:dynamodb:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:table/${aws_dynamodb_table.iamusertool_config.name}"
        },
        {
            "Sid": "AccessNeededByTestsIAMGroups",
            "Action": [
                "iam:CreateGroup",
                "iam:DeleteGroup",
                "iam:AttachGroupPolicy",
                "iam:DetachGroupPolicy"
            ],
            "Effect": "Allow",
            "Resource": "arn:aws:iam::${data.aws_caller_identity.current.account_id}:group/iamtool_*"
        },
        {
            "Sid": "AccessNeededByTestsIAMUsers",
            "Action": [
                "iam:CreateUser",
                "iam:DeleteUser"
            ],
            "Effect": "Allow",
            "Resource": "arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/iamtool_*"
        },
        {
            "Sid": "AccessNeededByTestsIAMPolicies",
            "Action": [
                "iam:CreatePolicy",
                "iam:DeletePolicy"
            ],
            "Effect": "Allow",
            "Resource": "arn:aws:iam::${data.aws_caller_identity.current.account_id}:policy/iamtool_*"
        }

    ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "aws-iam-user-tool_attach" {
  role       = "${aws_iam_role.aws-iam-user-tool.name}"
  policy_arn = "${aws_iam_policy.aws-iam-user-tool.arn}"
}
