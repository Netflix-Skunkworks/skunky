package main

import (
	"log"
	"encoding/json"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/service/sqs"
)

const (
	QueueUrl    = "https://sqs.<region>.amazonaws.com/<account number>/skunky"
	Region      = "us-west-2"
)

func main() {

	// Create a Session to use to pull the identity document
	// The Region is set for the SQS message and doesn't affect the ec2metadata call
	sess := session.Must(session.NewSession(&aws.Config{
				Region:      aws.String(Region),
	}))

	// Create a ec2metadata object
	ec2metadata_svc := ec2metadata.New(sess)

	// Request the identity doc
	identity, err := ec2metadata_svc.GetInstanceIdentityDocument()
	if err != nil {
		log.Fatal(err)
	}

	// Marshal the identity document into a json byte array
	b, err := json.Marshal(identity)

	// Create the SQS Service Endpoint
	sqs_svc := sqs.New(sess)

	// Fill out the send parameters for the SQS Message.  In this case, it's just the identity doc
	send_params := &sqs.SendMessageInput{
		MessageBody:  aws.String(string(b)), 				// Required
		QueueUrl:     aws.String(QueueUrl),      	// Required
	}

	// Send the SQS message and error out if it doesn't work
	// We don't care about the Message ID so just throw it away
	_, err = sqs_svc.SendMessage(send_params)
	if err != nil {
		log.Fatal(err)
	}

}
