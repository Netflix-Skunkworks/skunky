import boto3
import json
import logging
import os
from skunky.skunky import Skunky

logging.basicConfig(level=logging.DEBUG)
logging.debug("Using on-lambda IAM credentials")
Session = boto3.Session()

def lambda_handler(event, context=None):
    print(json.dumps(event))

    skunky = Skunky(session=Session, config='config.json')
    skunky.run()

    print("Time remaining (MS):", context.get_remaining_time_in_millis())
