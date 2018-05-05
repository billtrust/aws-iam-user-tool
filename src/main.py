# -*- coding: utf-8 -*-
import os
import sys
import argparse
import iamutils

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("command", nargs='*',
                        choices=["create"],
                        help="The command to be executed")
    parser.add_argument("--user-name", required=True)
    parser.add_argument("--user-email", required=True)
    parser.add_argument("--iam-group", action="append")

    try:
        args = parser.parse_args()
    except argparse.ArgumentError as exc:
        print(exc.message, '\n', exc.argument)

    # throws an exception if required environment variables aren't present
    # they are defined in the Dockerfile
    iamutils.ensure_envvars()

    if 'create' in args.command:
        if iamutils.user_exists(args.user_name):
            print("IAM User {} already exists!".format(args.user_name))
            sys.exit(1)
        iamutils.provision_user(
            user_name=args.user_name,
            group_names=args.iam_group,
            user_email=args.user_email,
            ses_email_template_name=os.environ.get(
                "IAMTOOL_SES_TEMPLATE_NAME", "iamtool_welcome")
        )
    else:
        parser.print_help()
