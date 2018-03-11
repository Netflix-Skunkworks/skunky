Skunky
========
![OSS Status](https://img.shields.io/badge/NetflixOSS-active-brightgreen.svg)

<img align="center" alt="Skunky Logo" src="docs/images/SkunkySmall.png" width="10%" display="block">

Skunky is an event based system focused on marking EC2 instances dirty based on events like SSH.  In an immutable world, when a person connects to a system through SSH, you can no longer guarantee that the system state is the same as when it booted.  Its goal is to enable maintaining immutable infrastructure as well as act as an intelligence source for other system level events.

Skunky is written for use in AWS.

## Install:

```bash
mkvirtualenv skunky
git clone git@github.com:Netflix-Skunkworks/skunky.git
cd skunky
pip install -e .
```

## IAM Permissions:

Skunky needs an IAM Role in each account that will be used to mark instances dirty.  Additionally, Skunky needs to be launched with a role which can `sts:AssumeRole` into the different account roles.

SkunkyLambdaProfile:
- IAM Role that Skunky Lambda function uses
- Needs the ability to call `sts:AssumeRole` into all of the Skunky's roles in other accounts
- Needs to be able to write to the DynamoDB table in your account
- Needs permissions to do things based on plugins you write

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": "sts:AssumeRole",
            "Effect": "Allow",
            "Resource": "arn:aws:iam::*:role/Skunky"
        },
        {
            "Action": [
                "dynamodb:DeleteItem",
                "dynamodb:GetItem",
                "dynamodb:GetRecords",
                "dynamodb:PutItem",
                "dynamodb:UpdateItem",
                "dynamodb:UpdateTable"
            ],
            "Effect": "Allow",
            "Resource": "arn:aws:dynamodb:<region>:<account-number>:table/Skunky"
        },
        {
            "Action": [
                "sqs:DeleteMessage",
                "sqs:DeleteMessageBatch",
                "sqs:ListQueues",
                "sqs:ReceiveMessage",
                "sqs:GetQueueUrl"
            ],
            "Effect": "Allow",
            "Resource": "arn:aws:sqs:<region>:<account-number>:skunky"
        },
        {
            "Effect": "Allow",
            "Action": [
                "logs:*"
            ],
            "Resource": "arn:aws:logs:*:*:*"
        }
    ]
}
```

Skunky:
- Must exist in every account to mark instance dirty.
- Must have a trust policy allowing `SkunkyLambdaProfile` in the account that is running the Skunky lambda.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "ec2:CreateTags"
      ],
      "Condition": {
          "ForAllValues:StringEquals": {
              "aws:TagKeys": [
                  "dirty"
              ]
          }
      },
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
```

Skunky Managed Policy:
- Must exist in each account as well to make sure that other roles cannot modify the Skunky tag.  If you really want to just have the DynamoDB portion and don't care about the EC2 tag, you can ignore this

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "sqs:SendMessage"
            ],
            "Resource": [
                "arn:aws:sqs:<region>:<account_number>:skunky"
            ]
        },
        {
            "Effect": "Deny",
            "Action": [
                "ec2:CreateTags",
                "ec2:DeleteTags"
            ],
            "Condition": {
                "ForAllValues:StringEquals": {
                    "aws:TagKeys": [
                        "dirty"
                    ]
                }
            },
            "Resource": [
                "*"
            ]
        }
    ]
}
```

## Sample Client:

A sample Golang client can be found under the `client` directory.  An example use case is to build this into a binary and place it into your Base AMI.  From there you could use something like PAM to execute each time someone logs into the system.  

Using a managed policy attached to each role, you could make sure each system has the permissions to make the Skunky tag.