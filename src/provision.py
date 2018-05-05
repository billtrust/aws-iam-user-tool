#!/usr/bin/python

# this script intended to be run inside docker
import os
import argparse
import iamutils

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("--region", required=False)
    parser.add_argument("--tfstate-bucket", required=True,
                        help="The S3 bucket name containing your Terraform state files. Can be any private S3 bucket.")
    parser.add_argument("--tfstate-dynamotable", required=True,
                        help="The DynamoDB table name which contains the Terraform state locks. Can be any table " +
                        "name if you have not setup Terraform state previously.")
    parser.add_argument("--email-from-address", required=True,
                        help="When the email is sent to the new user, it will come from this address.")
    parser.add_argument("--email-replyto-address", required=True,
                        help="When the email is sent to the new user, it will use this as the replyto address.")
    parser.add_argument("--email-bcc-address", required=False,
                        help="This is an optional bcc address for the email that is sent to the new user.")

    try:
        args = parser.parse_args()
    except argparse.ArgumentError as exc:
        print(exc.message, '\n', exc.argument)

    # if region argument absent, try to fill it from the environment
    if not args.region:
        args.region = os.environ.get("AWS_DEFAULT_REGION", None)
    if not args.region:
        raise Exception("AWS Region not specified!")

    print("""
***
NOTE: If you have updated your email template be sure to rebuild the
docker container prior to running this setup script so any changes
to /content are included.
***
    """)

    # run css inliner
    os.system("""
        python -m premailer \
               -f /content/welcome_email.html \
               -o /content/welcome_email_cssinline.html
        """)

    # apply the ses template with terraform
    os.chdir("/terraform")
    os.system(f"""
        terraform init \
            -backend-config="region={args.region}" \
            -backend-config="bucket={args.tfstate_bucket}" \
            -backend-config="dynamodb_table={args.tfstate_dynamotable}"
        """)
    os.system("terraform apply -auto-approve")

    iamutils.set_email_config(
        email_from=args.email_from_address,
        email_replyto=args.email_replyto_address,
        email_bcc=args.email_bcc_address if args.email_bcc_address else None
    )
