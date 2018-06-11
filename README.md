# AWS IAM User Tool

A command line tool to create AWS IAM users, set permissions, and send a welcome email to the newly created user with all necessary login and usage information.

See a [sample](http://htmlpreview.github.io/?https://github.com/billtrust/aws-iam-user-tool/blob/master/sample_email.html) of the welcome email this tool sends out when creating a new IAM user.

## Features

* Create the user and assign to the specified IAM groups.
* Encrypts the password via Privnote.com for secure distribution with self destruct after the password link is clicked.
* Auto discovers your account's password policy and includes these details in the welcome email.
* Auto discovers your cross account IAM role configuration and includes switch account URLs in the welcome email.
* Auto discovers your account's login URL with alias and includes this in the welcome email.
* Emails the user a welcome email with all necessary information to setup MFA and access their account.

## Build

```
docker build -t billtrust/aws-iam-user-tool:latest .
```

## Setup

### Setup - One time Creation of AWS Resources and Setting Configuration

To run the Terraform script to create the SES email template and other AWS resources, the below is required to run one as a pre-requisite.  If the `/content/welcome_email.html` template changes, this will need to be run again.  This will also run the premailer program to inline the css and create the `/content/welcome_email_cssinline.html` file.

```
docker run \
    -e AWS_ACCESS_KEY_ID=<<YOURKEY>> \
    -e AWS_SECRET_ACCESS_KEY=<<YOURSECRET>> \
    -e AWS_DEFAULT_REGION=us-east-1 \
    --entrypoint python \
    billtrust/aws-iam-user-tool:latest \
    /src/provision.py \
    --tfstate-bucket mycompany-tfstate \
    --tfstate-dynamotable tfstate \
    --email-from-address noreply@aws-dev.billtrust.com \
    --email-replyto-address noreply@aws-dev.billtrust.com \
    --email-bcc-address this-is-optional@mycompany.com
```

The AWS creds provided above must be sufficient to create/access all AWS resosurces required, including IAM, SES, S3, and DynamoDb (for Terraform state).  See the "terraform" folder to see exactly which resources are created.  Terraform is configured here to remotely store its tfstate files in S3.  As such, the creds you supply additionally need to be able to read and write from the S3 bucket you designate via the `--tfstate-bucket` argument your administrative creds, and the DyanamoDB table you designate via the `--tfstate-dynamotable` argument.

### Setup - Terraform RemoteState Bucket

If you have not yet setup remote state in Terraform, you'll just need to create the S3 bucket you want to use for state.  Terraform will take care of writing to it and creating the DynamoDB lock table.  This is the bucket name referred to in the above argument `--tfstate-bucket`.

You can create a bucket however you like, including by the following AWS CLI command:

```
aws s3api create-bucket --bucket mycompany-terraform-tfstate --region us-east-1 --acl private
```

### Setup - SES Domain Verification

SES will not send emails until you have verified a domain for use with SES.  If you have not already configured SES for use with your email, see the instructions below:

Verifying a Domain With Amazon SES:
https://docs.aws.amazon.com/ses/latest/DeveloperGuide/verify-domain-procedure.html

Or to verify just a single email address for testing:
https://docs.aws.amazon.com/ses/latest/DeveloperGuide/verify-email-addresses-procedure.html

## Prerequisites

You will need the following installed on your workstation to use this tool.

* Docker
* Python
* Boto3 - `pip install boto3` if not already installed
* A default AWS profile which has credentials to assume the role `bt-policy-aws-iam-user-tool`.  If you would like to use a different profile, change the `--local-aws-profile` argument to specify the profile name.

## Usage

To create a user execute `iamtool.py` passing arguments for the username, email, and IAM groups the user should belong to.

Example:
```shell
# make sure to build first, the image is not currently published to docker hub
docker build -t billtrust/aws-iam-user-tool:latest .
# iamtool.py generates AWS temp credentials and executes the tool within a container
python ./iamtool.py \
    create \
    --user-name testuser \
    --user-email testuser@mycompany.com \
    --iam-group master-allusers \
    --iam-group dev-developers \
    --iam-group stage-developers \
    --iam-group prod-developers \
    --region us-east-1 \
    --profile default
```

## Run Tests

To run unit tests simply execute `python run_tests.py` which will run the unit tests inside the container.

## License

MIT License

Copyright (c) 2018 Factor Systems Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
