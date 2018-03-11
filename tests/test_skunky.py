#!/usr/bin/env python

import boto3
from botocore import exceptions
import json
import logging
import time
import unittest
from mock import patch, Mock, PropertyMock, MagicMock

from skunky.aws.lambdakickass import LambdaKickass
from skunky.skunky import Skunky


class SkunkyTestCase(unittest.TestCase):

    @patch('boto3.Session', autospec=True)
    def test_skunky__init(self, session_mock):
        testSkunky = Skunky(session_mock)

        assert testSkunky.dynamodb_table_name == 'Skunky'
        assert testSkunky.queue_name == 'skunky'
        assert testSkunky.to_be_skunked == {}

    @patch('boto3.Session', autospec=True)
    def test_get_queue_url(self, session_mock):

        sqs_client_mock = Mock()
        sqs_client_mock.get_queue_url.return_value = {
            'QueueUrl': 'https://queue.amazonaws.com/123456789101112/MyQueue',
            'ResponseMetadata': {
            },
        }

        testSkunky = Skunky(session_mock)
        testSkunky.sqs_client = sqs_client_mock

        assert testSkunky.get_queue_url() == 'https://queue.amazonaws.com/123456789101112/MyQueue'

    @patch('boto3.Session', autospec=True)
    def test_add_to_skunk_single_region(self, session_mock):
        identity = TEST_IDENTITY_1_A_US_WEST_2

        testSkunky = Skunky(session_mock)

        testSkunky.add_to_skunk(identity)

        assert len(testSkunky.to_be_skunked['000000000001']['us-west-2']) == 1

    @patch('boto3.Session', autospec=True)
    def test_add_to_skunk_multiple_regions(self, session_mock):

        testSkunky = Skunky(session_mock)

        testSkunky.add_to_skunk(TEST_IDENTITY_1_A_US_WEST_2)
        testSkunky.add_to_skunk(TEST_IDENTITY_1_A_US_EAST_1)

        assert len(testSkunky.to_be_skunked['000000000001']['us-west-2']) == 1
        assert len(testSkunky.to_be_skunked['000000000001']['us-east-1']) == 1

    @patch('boto3.Session', autospec=True)
    def test_add_to_skunk_single_region_multiple_instances(self, session_mock):

        testSkunky = Skunky(session_mock)

        testSkunky.add_to_skunk(TEST_IDENTITY_1_A_US_WEST_2)
        testSkunky.add_to_skunk(TEST_IDENTITY_2_A_US_WEST_2)

        assert len(testSkunky.to_be_skunked['000000000001']['us-west-2']) == 2

    @patch('boto3.Session', autospec=True)
    def test_receive_identities_from_queue_single(self, session_mock):

        sqs_client_mock = Mock()
        sqs_client_mock.receive_message.return_value = {
            'Messages': [
                {
                    'MessageId': '123',
                    'ReceiptHandle': 'handle123',
                    'MD5OfBody': 'md5123',
                    'Body': json.dumps(TEST_IDENTITY_1_A_US_WEST_2['identity']),
                    'MD5OfMessageAttributes': 'string',
                    'Attributes': {
                        'SentTimestamp': '123123123'
                    }
                },
            ]
        }

        testSkunky = Skunky(session_mock)
        testSkunky.sqs_client = sqs_client_mock

        testSkunky.receive_identities_from_queue()

        assert len(testSkunky.to_be_skunked['000000000001']['us-west-2']) == 1

    @patch('boto3.Session', autospec=True)
    def test_receive_identities_from_queue_multiple(self, session_mock):

        sqs_client_mock = Mock()
        sqs_client_mock.receive_message.return_value = {
            'Messages': [
                {
                    'MessageId': '123',
                    'ReceiptHandle': 'handle123',
                    'MD5OfBody': 'md5123',
                    'Body': json.dumps(TEST_IDENTITY_1_A_US_WEST_2['identity']),
                    'MD5OfMessageAttributes': 'string',
                    'Attributes': {
                        'SentTimestamp': '123123123'
                    }
                },
                {
                    'MessageId': '124',
                    'ReceiptHandle': 'handle124',
                    'MD5OfBody': 'md5124',
                    'Body': json.dumps(TEST_IDENTITY_1_B_US_EAST_1['identity']),
                    'MD5OfMessageAttributes': 'string',
                    'Attributes': {
                        'SentTimestamp': '123123124'
                    }
                },
            ]
        }

        testSkunky = Skunky(session_mock)
        testSkunky.sqs_client = sqs_client_mock

        testSkunky.receive_identities_from_queue()

        assert len(testSkunky.to_be_skunked['000000000001']['us-west-2']) == 1
        assert len(testSkunky.to_be_skunked['000000000002']['us-east-1']) == 1

    @patch('boto3.Session', autospec=True)
    def test_identity_hash(self, session_mock):

        testSkunky = Skunky(session_mock)

        assert testSkunky.hash(TEST_IDENTITY_1_A_US_WEST_2) == TEST_IDENTITY_1_A_US_WEST_2_HASH

    mock_time = Mock()
    mock_time.return_value = 0

    @patch('time.time', mock_time)
    @patch.object(Skunky, '_start')
    @patch('boto3.Session', autospec=True)
    def test_run(self, session_mock, skunky_start_mock):

        testSkunky = Skunky(session_mock)
        testSkunky.run()

        assert testSkunky.expire == TIME_RUN

    @patch('time.time', mock_time)
    @patch('boto3.Session', autospec=True)
    def test_ttl(self, session_mock):

        testSkunky = Skunky(session_mock)

        assert testSkunky.ttl() == TTL_TIME

    @patch.object(Skunky,'tag')
    @patch.object(Skunky,'put')
    @patch('boto3.Session', autospec=True)
    def test_skunk_1_account_1_region_single_instance(self, session_mock, skunky_put_mock, skunky_tag_mock):

        testSkunky = Skunky(session_mock)
        testSkunky.add_to_skunk(TEST_IDENTITY_1_A_US_WEST_2)
        testSkunky.skunk_instances()

        assert skunky_put_mock.call_count == 1
        assert skunky_tag_mock.call_count == 1
        assert len(testSkunky.to_be_skunked['000000000001']['us-west-2']) == 0

    @patch.object(Skunky,'tag')
    @patch.object(Skunky,'put')
    @patch('boto3.Session', autospec=True)
    def test_skunk_1_account_1_region_multiple_instances(self, session_mock, skunky_put_mock, skunky_tag_mock):

        testSkunky = Skunky(session_mock)
        testSkunky.add_to_skunk(TEST_IDENTITY_1_A_US_WEST_2)
        testSkunky.add_to_skunk(TEST_IDENTITY_2_A_US_WEST_2)
        testSkunky.skunk_instances()

        assert skunky_put_mock.call_count == 2
        assert skunky_tag_mock.call_count == 1
        assert len(testSkunky.to_be_skunked['000000000001']['us-west-2']) == 0

    @patch.object(Skunky,'tag')
    @patch.object(Skunky,'put')
    @patch('boto3.Session', autospec=True)
    def test_skunk_2_accounts_2_regions_multiple_instances(self, session_mock, skunky_put_mock, skunky_tag_mock):

        testSkunky = Skunky(session_mock)
        testSkunky.add_to_skunk(TEST_IDENTITY_1_A_US_WEST_2)
        testSkunky.add_to_skunk(TEST_IDENTITY_2_A_US_WEST_2)
        testSkunky.add_to_skunk(TEST_IDENTITY_1_A_US_EAST_1)
        testSkunky.add_to_skunk(TEST_IDENTITY_1_B_US_EAST_1)
        testSkunky.skunk_instances()

        assert skunky_put_mock.call_count == 4
        assert skunky_tag_mock.call_count == 3
        assert len(testSkunky.to_be_skunked['000000000001']['us-west-2']) == 0
        assert len(testSkunky.to_be_skunked['000000000001']['us-east-1']) == 0
        assert len(testSkunky.to_be_skunked['000000000002']['us-east-1']) == 0

    @patch('boto3.Session', autospec=True)
    def test_skunky_put_identity_dynamodb_true(self, session_mock):

        testSkunky = Skunky(session_mock)

        self.assertTrue(testSkunky.put(TEST_IDENTITY_1_A_US_WEST_2))

    @patch('boto3.Session', autospec=True)
    def test_skunky_put_identity_dynamodb_false(self, session_mock):

        response = {
            'Error': {
                'Code': "ConditionalCheckFailedException"
            }
        }

        dynamodb_table_mock = Mock()
        dynamodb_table_mock.put_item.side_effect = exceptions.ClientError(response, 'put_item')

        testSkunky = Skunky(session_mock)
        testSkunky.dynamodb_table = dynamodb_table_mock

        self.assertFalse(testSkunky.put(TEST_IDENTITY_1_A_US_WEST_2))

    @patch('boto3.Session', autospec=True)
    def test_skunky_put_identity_dynamodb_raise_error(self, session_mock):

        dynamodb_table_mock = Mock()
        dynamodb_table_mock.put_item.side_effect = Exception('Some unknown exception')

        testSkunky = Skunky(session_mock)
        testSkunky.dynamodb_table = dynamodb_table_mock

        self.assertRaises(Exception, lambda: testSkunky.put(TEST_IDENTITY_1_A_US_WEST_2))


TTL_TIME = 2592000
TIME_RUN = (5 * 60) - 15

TEST_IDENTITY_1_A_US_WEST_2_HASH = '000000000001::us-west-2::i-xxxxxxxxxxxxxxxx1::123123123'

TEST_IDENTITY_1_A_US_WEST_2 = {
    "identity": {
        "devpayProductCodes": None,
        "availabilityZone": "us-nflx-1a",
        "privateIp": '10.0.0.1',
        "version": "2010-08-31",
        "instanceId": "i-xxxxxxxxxxxxxxxx1",
        "billingProducts": None,
        "instanceType": "m3.medium",
        "accountId": "000000000001",
        "architecture": "x86_64",
        "kernelId": "aki-fc8f11cc",
        "ramdiskId": None,
        "imageId": "ami-12345678",
        "pendingTime": "2017-04-11T18:12:03Z",
        "region": "us-west-2"
    },
    "dirty_timestamp": 123123123,
    "receipt_handle": 'receipthandle1'
}

TEST_IDENTITY_2_A_US_WEST_2 = {
    "identity": {
        "devpayProductCodes": None,
        "availabilityZone": "us-nflx-1a",
        "privateIp": '10.0.0.2',
        "version": "2010-08-31",
        "instanceId": "i-xxxxxxxxxxxxxxxx2",
        "billingProducts": None,
        "instanceType": "m3.medium",
        "accountId": "000000000001",
        "architecture": "x86_64",
        "kernelId": "aki-fc8f11cc",
        "ramdiskId": None,
        "imageId": "ami-12345678",
        "pendingTime": "2017-04-11T18:12:03Z",
        "region": "us-west-2"
    },
    "dirty_timestamp": 123123124,
    "receipt_handle": 'receipthandle2'
}

TEST_IDENTITY_1_A_US_EAST_1 = {
    "identity": {
        "devpayProductCodes": None,
        "availabilityZone": "us-nflx-1a",
        "privateIp": '10.1.0.1',
        "version": "2010-08-31",
        "instanceId": "i-xxxxxxxxxxxxxxxx3",
        "billingProducts": None,
        "instanceType": "m3.medium",
        "accountId": "000000000001",
        "architecture": "x86_64",
        "kernelId": "aki-fc8f11cc",
        "ramdiskId": None,
        "imageId": "ami-12345678",
        "pendingTime": "2017-04-11T18:12:03Z",
        "region": "us-east-1"
    },
    "dirty_timestamp": 123123125,
    "receipt_handle": 'receipthandle3'
}

TEST_IDENTITY_1_B_US_EAST_1 = {
    "identity": {
        "devpayProductCodes": None,
        "availabilityZone": "us-nflx-1a",
        "privateIp": '10.0.0.1',
        "version": "2010-08-31",
        "instanceId": "i-xxxxxxxxxxxxxxxx4",
        "billingProducts": None,
        "instanceType": "m3.medium",
        "accountId": "000000000002",
        "architecture": "x86_64",
        "kernelId": "aki-fc8f11cc",
        "ramdiskId": None,
        "imageId": "ami-12345678",
        "pendingTime": "2017-04-11T18:12:03Z",
        "region": "us-east-1"
    },
    "dirty_timestamp": 123123126,
    "receipt_handle": 'receipthandle4'
}

if __name__ == '__main__':
    logging.disable(logging.INFO)
    logging.disable(logging.DEBUG)
    unittest.main()