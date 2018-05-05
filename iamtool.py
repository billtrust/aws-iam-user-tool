#!/usr/bin/python
from __future__ import print_function

import os
import sys
import argparse
import tempfile
import subprocess
import uuid
import re
import boto3
from string import Template


def get_aws_temp_creds(role_name, profile_name = None):
    if profile_name:
        session = boto3.Session(profile_name=profile_name)
        sts_client = session.client('sts')
        iam_client = session.client('iam')
    else:
        sts_client = boto3.client('sts')
        iam_client = boto3.client('iam')

    try:
        role_arn = iam_client.get_role(RoleName=role_name)['Role']['Arn']
    except Exception as e:
        print("Error reading role arn for role name {}: {}".format(role_name, e))
        raise

    try:
        random_session = uuid.uuid4().hex
        assumed_role_object = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName="docker-session-{}".format(random_session),
            DurationSeconds=3600  # 1 hour max
        )
        access_key = assumed_role_object["Credentials"]["AccessKeyId"]
        secret_key = assumed_role_object["Credentials"]["SecretAccessKey"]
        session_token = assumed_role_object["Credentials"]["SessionToken"]
    except Exception as e:
        print("Error assuming role {}: {}".format(role_arn, e))
        raise

    print("Generated temporary AWS credentials: {}".format(access_key))
    return access_key, secret_key, session_token


def exec_command(command):
    # print(command)
    output = ""
    try:
        p = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
        p_status = p.wait()
        (output, err) = p.communicate()
        output = output.decode("utf-8")
        # print (output)
    except Exception as e:
        print ("Error: Output: {} \nException:{}".format(output, str(e)))
        return 1, output, -1
    return p.returncode, output


def single_line_string(string):
    # replace all runs of whitespace to a single space
    string = re.sub('\s+', ' ', string)
    # remove newlines
    string = string.replace('\n', '')
    return string


def get_docker_inspect_exit_code(container_name):
    inspect_command = "docker inspect {} --format='{{{{.State.ExitCode}}}}'".format(
        container_name)
    (returncode, output) = exec_command(inspect_command)
    if not returncode == 0:
        print("Error from docker (docker exit code {}) inspect trying to get container exit code, output: {}".format(returncode, output))
        sys.exit(1)

    try:
        container_exit_code = int(output.replace("'", ""))
    except Exception as e:
        print("Error parsing exit code from docker inspect, raw output: {}".format(output))
        sys.exit(1)

    # pass along the exit code from the container
    print("Container exited with code {}".format(container_exit_code))
    return container_exit_code


def remove_docker_container(container_name):
    print("Removing container: {}".format(container_name))
    remove_command = "docker rm {}".format(container_name)
    (returncode, output) = exec_command(remove_command)
    if not returncode == 0:
        print("Error removing named container! Run 'docker container prune' to cleanup manually.")


def random_container_name():
    return uuid.uuid4().hex


def generate_temp_env_file(
    access_key,
    secret_key,
    session_token,
    region):
    envs = []
    envs.append("AWS_ACCESS_KEY_ID=" + access_key)
    envs.append("AWS_SECRET_ACCESS_KEY=" + secret_key)
    envs.append("AWS_SESSION_TOKEN=" + session_token)
    envs.append("AWS_DEFAULT_REGION=" + region)
    envs.append("AWS_REGION=" + region)
    envs.append("PYTHONUNBUFFERED=1")
    if os.environ.get('APP_LOGLEVEL', None):
        envs.append("APP_LOGLEVEL=" + os.environ['APP_LOGLEVEL'])
    
    temp_env_file = tempfile.NamedTemporaryFile(delete=False, mode="w")
    for item in envs:
        temp_env_file.write("%s\n" % item)
    temp_env_file.close()
    print("Temp envs file: {}".format(temp_env_file.name))
    return temp_env_file.name

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("command", nargs='*',
                        choices=["create"],
                        help="The command to be executed")
    parser.add_argument("--user-name", required=True)
    parser.add_argument("--user-email", required=True)
    parser.add_argument("--iam-group", required=False, action="append")
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--profile",
                        help="The AWS creds used on your laptop to generate the STS temp credentials")

    try:
        args = parser.parse_args()
    except argparse.ArgumentError as exc:
        print(exc.message, '\n', exc.argument)

    access_key, secret_key, session_token = \
        get_aws_temp_creds("role-aws-iam-user-tool", args.profile)

    env_tmpfile = generate_temp_env_file(
        access_key,
        secret_key,
        session_token,
        args.region
        )

    if 'create' in args.command:
        cmd = "create --user-name {} --user-email {}".format(
            args.user_name, args.user_email)
        for group in args.iam_group:
            cmd += " --iam-group {}".format(group)

    container_name = random_container_name()
    command = Template(single_line_string("""
        docker run
            --name $container_name 
            --env-file $env_tmpfile
            billtrust/aws-iam-user-tool:latest
            $cmd
        """)) \
        .substitute({
            'env_tmpfile': env_tmpfile,
            'container_name': container_name,
            'cmd': cmd
        })

    print(command)
    os.system(command)

    exit_code = get_docker_inspect_exit_code(container_name)
    remove_docker_container(container_name)
    os.remove(env_tmpfile)

    sys.exit(exit_code)
