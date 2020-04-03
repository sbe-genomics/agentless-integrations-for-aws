package main

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/honeycombio/agentless-integrations-for-aws/common"
	"github.com/sirupsen/logrus"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/honeycombio/honeytail/httime"
	"github.com/honeycombio/honeytail/parsers"
	"github.com/honeycombio/libhoney-go"
)

// Response is a simple structured response
type Response struct {
	Ok      bool   `json:"ok"`
	Message string `json:"message"`
}

var parser parsers.LineParser
var parserType, timeFieldName, timeFieldFormat, env string
var verboseMode bool

func Handler(request events.CloudwatchLogsEvent) (Response, error) {
	if parser == nil {
		return Response{
			Ok:      false,
			Message: "parser not initialized, cannot process events",
		}, fmt.Errorf("parser not initialized, cannot process events")
	}

	data, err := request.AWSLogs.Parse()
	if err != nil {
		return Response{
			Ok:      false,
			Message: fmt.Sprintf("failed to parse cloudwatch event data: %s", err.Error()),
		}, err
	}
	for _, event := range data.LogEvents {
		logrus.WithField("line", event.Message).Debug("got line")

		parsedLine, err := parser.ParseLine(event.Message)
		if err != nil {
			logrus.WithError(err).WithField("line", event.Message).
				Warn("unable to parse line")
			common.WriteErrorEvent(err, "parse error", map[string]interface{}{
				"meta.raw_message": event.Message,
			})
			continue
		}
		hnyEvent := libhoney.NewEvent()

		timestamp := httime.GetTimestamp(parsedLine, timeFieldName, timeFieldFormat)
		hnyEvent.Timestamp = timestamp

		// convert ints and floats if necessary
		if parserType != "json" {
			hnyEvent.Add(common.ConvertTypes(parsedLine))
		} else {
			hnyEvent.Add(parsedLine)
		}

		hnyEvent.AddField("env", env)
		hnyEvent.AddField("aws.cloudwatch.group", data.LogGroup)
		hnyEvent.AddField("aws.cloudwatch.stream", data.LogStream)
		// Pass the line off as metadata so we can match responses to original lines
		hnyEvent.Metadata = event.Message
		fields := hnyEvent.Fields()
		for _, field := range common.GetFilterFields() {
			delete(fields, field)
		}
		hnyEvent.Send()
	}

	wg := sync.WaitGroup{}
	if verboseMode {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Create a local reference to the response chan, as Flush will close and recreate
			// the one returned by TxReponses()
			respChan := libhoney.TxResponses()
			for resp := range respChan {
				e := logrus.WithFields(logrus.Fields{
					"line":          resp.Metadata,
					"response_code": resp.StatusCode,
					"response_body": resp.Body,
					"duration_ms":   resp.Duration / time.Millisecond,
				})
				if resp.Err != nil {
					e.WithField("error", resp.Err.Error())
				}
				e.Debug("response from honeycomb")
			}
		}()
	}

	libhoney.Flush()
	wg.Wait()

	return Response{
		Ok:      true,
		Message: "ok",
	}, nil
}

func main() {
	var err error
	if err = common.InitHoneycombFromEnvVars(); err != nil {
		logrus.WithError(err).
			Fatal("Unable to initialize libhoney with the supplied environment variables")
		return
	}
	defer libhoney.Close()

	parserType = os.Getenv("PARSER_TYPE")
	parser, err = common.ConstructParser(parserType)
	if err != nil {
		logrus.WithError(err).WithField("parser_type", parserType).
			Fatal("unable to construct parser")
		return
	}
	common.AddUserAgentMetadata("cloudwatch", parserType)

	logrus.SetLevel(logrus.InfoLevel)

	env = os.Getenv("ENVIRONMENT")
	timeFieldName = os.Getenv("TIME_FIELD_NAME")
	timeFieldFormat = os.Getenv("TIME_FIELD_FORMAT")
	if os.Getenv("VERBOSE") != "" {
		verboseMode = true
		logrus.SetLevel(logrus.DebugLevel)
	}

	lambda.Start(Handler)
}
