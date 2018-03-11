#!/usr/bin/env python
import hashlib
import json
import logging
import logging.config
import os
import sys
import time
from multiprocessing import Process


import boto3
from botocore.exceptions import ClientError
from decimal import Decimal
import import_string

from skunky.aws.lambdakickass import LambdaKickass

__version__ = '0.1.0'

LOGGER = None

logging.getLogger('boto3').setLevel(logging.CRITICAL)
logging.getLogger('botocore').setLevel(logging.CRITICAL)
Session = boto3.Session()


class Filter(object):
    def __init__(self, config=None):
        self.config = config

    def apply(self, input_list):
        raise NotImplementedError


class Auditor(object):
    def __init__(self, config=None):
        self.config = config

    def audit(self, input_list):
        raise NotImplementedError


class Skunky(object):

    def __init__(self, session, config='config.json', ttl_time=2592000, time_run=285):
        self.config = self._init_config(config)
        self._init_logging()
        self.session = session
        self.region = self.config.get('region', 'us-west-2')
        self.ttl_time = self.config.get('ttl_time', 2592000)
        self.time_run = self.config.get('time_run', 285)
        self.lk = LambdaKickass(session=self.session)
        self.sqs_client = self.session.client('sqs', region_name=self.region)
        self.dynamodb_resource = self.session.resource('dynamodb', region_name=self.region)
        self.dynamodb_table_name = 'Skunky'
        self.dynamodb_table = self.dynamodb_resource.Table(self.dynamodb_table_name)
        self.queue_name = 'skunky'
        self.queue_url = self.get_queue_url()
        self.to_be_skunked = {}
        self.time_start = Decimal(time.time())
        self.expire = None
        self.active_filters = self.config.get('ACTIVE_FILTERS', [])
        self.active_auditors = self.config.get('ACTIVE_AUDITORS', [])
        self.filter_plugins = []
        self.auditor_plugins = []

    def _init_logging(self):
        global LOGGER
        logging.config.dictConfig(self.config['logging'])
        LOGGER = logging.getLogger(__name__)

    def _init_config(self, config_file):
        try:
            with open(os.path.join(os.getcwd(), config_file), 'r') as f:
                config = json.load(f)
                return config
        except IOError:
            LOGGER.fatal("Unable to load config from {}!".format(config_file))

    def _load_filters(self):
        for filter_plugin in self.active_filters:
            cls = None
            try:
                cls = import_string(filter_plugin)
            except ImportError as e:
                LOGGER.warn("Unable to find plugin {}, exception: {}".format(filter_plugin, e))
            else:
                plugin = None
                try:
                    plugin = cls(config=self.config['filter_config'].get(cls.__name__))
                except KeyError:
                    plugin = cls()
                LOGGER.info('Loaded plugin {}'.format(filter_plugin))
                self.filter_plugins.append(plugin)

    def _load_auditors(self):
        for auditor_plugin in self.active_auditors:
            cls = None
            try:
                cls = import_string(auditor_plugin)
            except ImportError as e:
                LOGGER.warn("Unable to find plugin {}, exception: {}".format(auditor_plugin, e))
            else:
                plugin = None
                try:
                    plugin = cls(config=self.config['auditor_config'].get(cls.__name__))
                except KeyError:
                    plugin = cls()
                LOGGER.info('Loaded plugin {}'.format(auditor_plugin))
                self.auditor_plugins.append(plugin)

    def run(self):
        LOGGER.info("Skunky starting...")
        self.expire = self.time_start + self.time_run
        self._load_filters()
        self._load_auditors()
        self._start()

    def _start(self, silent=False):
        while True:
            if self.expire and time.time() > self.expire:
                LOGGER.warn("Skunky running out of time, starting fresh...")
                return

            self.receive_identities_from_queue()
            self.skunk_instances()

            time.sleep(1)

    def get_queue_url(self):
        response = self.sqs_client.get_queue_url(QueueName=self.queue_name)
        return response['QueueUrl']

    def receive_identities_from_queue(self):
        response = self.sqs_client.receive_message(QueueUrl=self.queue_url, AttributeNames=[
            'All'], WaitTimeSeconds=5, MaxNumberOfMessages=10)

        for message in response.get('Messages', []):
            identity = json.loads(message['Body'])

            skunk = {
                "identity": dict(identity),
                "dirty_timestamp": message['Attributes']['SentTimestamp'],
                "receipt_handle": message['ReceiptHandle']
            }

            self.add_to_skunk(skunk)

    def add_to_skunk(self, skunk):

        account_id = skunk['identity']['accountId']
        instance_region = skunk['identity']['region']

        for filter in self.filter_plugins:
            try:
                if filter.apply(skunk['identity']):
                    # If a filter say don't skunk then we return and don't add to list
                    return
            except Exception as e:
                LOGGER.error('Exception Caught in Filter Plugin - {}: {}'.format(filter, e))

        if self.to_be_skunked.get(account_id, '') == '':
            self.to_be_skunked[account_id] = {}
            self.to_be_skunked[account_id][instance_region] = []
            self.to_be_skunked[account_id][instance_region].append(skunk)
        elif self.to_be_skunked[account_id].get(instance_region, '') == '':
            self.to_be_skunked[account_id][instance_region] = []
            self.to_be_skunked[account_id][instance_region].append(skunk)
        else:
            self.to_be_skunked[account_id][instance_region].append(skunk)

    def delete_identity_from_queue(self, receipt_handle_list):
        delete_response = self.sqs_client.delete_message_batch(
            QueueUrl=self.queue_url, Entries=receipt_handle_list)

    def skunk_instances(self):
        for account, regions in self.to_be_skunked.items():
            for region, identities in self.to_be_skunked[account].items():
                instance_resources = []
                receipt_handles = []
                count = 0
                for skunk in self.to_be_skunked[account][region]:
                    # Add instance to DynamoDB table
                    if self.put(skunk):
                        count = count + 1
                        instance_resources.append(skunk['identity']['instanceId'])
                        receipt_handles.append({'Id': str(count), 'ReceiptHandle': skunk['receipt_handle']})

                        try:
                            for auditor in self.auditor_plugins:
                                proc = Process(target=auditor.audit, args=(skunk['identity'],))
                                proc.start()
                        except Exception as e:
                            LOGGER.error('Exception Caught in Auditor Plugin - {}: {}'.format(auditor, e))

                if len(self.to_be_skunked[account][region]) > 0:
                    if self.config.get('tag', True):
                        self.tag(account, region, instance_resources)
                    if count > 0:
                        self.delete_identity_from_queue(receipt_handles)

                self.to_be_skunked[account][region] = []

    def tag(self, account, region, instances):
        ec2_client = self.lk.connect_to_region(technology='ec2', account=account,
                                               region=region, profile="Skunky", session_id="skunkystinks")
        retry = [5, 5, 3, 3, 1, 1]
        added = False
        while len(retry) > 0 and not added:
            try:
                ec2_client.create_tags(
                    Resources=instances,
                    Tags=[
                        {
                            'Key': 'dirty',
                            'Value': 'skunked'
                        },
                    ]
                )
                added = True
            except ClientError:
                instance_string = ''
                for instance in instances:
                    instance_string = instance_string + instances + ","
                LOGGER.error("Failed to mark dirty the following instances in {}:{} - {}".format(account, region, region.instance_string))
                if len(retry) > 0:
                    retry_time = retry.pop()
                    logger.debug("Sleeping {} and retrying".format(retry_time))
                    time.sleep(retry_time)

    def put(self, skunk):
        """ Will create a new entry only if one doesn't already exist """
        item = {}
        item['hash'] = self.hash(skunk)
        item['instance_id'] = skunk['identity']['instanceId']
        item['skunk_level'] = skunk['identity'].get('skunk_level', 'unknown')
        item['account_id'] = skunk['identity']['accountId']
        item['region'] = skunk['identity']['region']
        item['marked_dirty'] = skunk['dirty_timestamp']
        item['identity'] = json.dumps(skunk['identity'])
        item['ttl'] = self.ttl()

        retry = [5, 5, 3, 3, 1, 1]
        added = False
        while len(retry) > 0 and not added:
            try:
                self.dynamodb_table.put_item(Item=item, ExpressionAttributeNames={"#h": "hash"},
                                             ConditionExpression="attribute_not_exists(#h)")
                added = True
            except ClientError as e:
                if "ConditionalCheckFailedException" == e.response['Error']['Code']:
                    return False

                if len(retry) > 0:
                    retry_time = retry.pop()
                    LOGGER.debug("Sleeping {} and retrying".format(retry_time))
                    time.sleep(retry_time)
            except Exception:
                raise

        return True

    def hash(self, skunk):
        return '{}::{}::{}::{}'.format(skunk['identity']['accountId'], skunk['identity']['region'],
                                       skunk['identity']['instanceId'], skunk['dirty_timestamp'])

    def ttl(self):
        return int(time.time() + self.ttl_time)


def main():
    try:
        skunky = Skunky(session=Session, config='config.json')
        skunky.run()
    except KeyboardInterrupt:
        logging.debug("Skunky exiting due to KeyboardInterrupt...")
