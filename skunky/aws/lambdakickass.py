#!/usr/bin/env python

import json

import boto3
from botocore.exceptions import ClientError


class LambdaKickass(object):
    def __init__(self, session):
        self.sts_connection = None
        self._assume_role_cache = {}
        self.sts = session.client("sts")
        return

    def assume_role(self, account, profile="Skunky", session_id="skunkystinks"):
        arn = "arn:aws:iam::{}:role/{}".format(account, profile)
        if arn not in self._assume_role_cache:
            try:
                self._assume_role_cache[arn] = self.sts.assume_role(RoleArn=arn, RoleSessionName=session_id)
            except ClientError as e:
                print(e)
        return {
            "aws_access_key_id": self._assume_role_cache[arn]['Credentials']['AccessKeyId'],
            "aws_secret_access_key": self._assume_role_cache[arn]['Credentials']['SecretAccessKey'],
            "aws_session_token": self._assume_role_cache[arn]['Credentials']['SessionToken']
        }

    def connect_to_region(self, technology, account, region='us-east-1', profile="Skunky", session_id="skunkystinks"):
        assumed_role = self.assume_role(account, profile=profile, session_id=session_id)
        session = boto3.Session(region_name=region, aws_access_key_id=assumed_role['aws_access_key_id'], aws_secret_access_key=assumed_role['aws_secret_access_key'], aws_session_token=assumed_role['aws_session_token'])
        client = session.client(technology, region_name=region)
        return client
