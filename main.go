package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/fadhilthomas/go-nuclei-slack/config"
	"github.com/fadhilthomas/go-nuclei-slack/model"
	"github.com/rs/zerolog/log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

var (
	attachmentList []model.SlackAttachmentBody
	blockList []model.SlackBlockBody
	vulnerabilityList []model.Output
)

func main() {
	config.Set(config.LOG_LEVEL, "info")
	webHookURL := config.GetStr(config.SLACK_TOKEN)

	database := model.OpenDB()
	if database == nil {
		return
	}
	summary := model.SummaryReport{}

	file, err := os.Open(config.GetStr(config.FILE_LOCATION))
	if err != nil {
		log.Error().Str("file", "main").Err(err)
	}
	fScanner := bufio.NewScanner(file)
	for fScanner.Scan() {
		result := model.Output{}
		err = json.Unmarshal([]byte(fScanner.Text()), &result)
		if err != nil {
			log.Error().Str("file", "slack").Err(err)
		}

		vulnerabilityList = append(vulnerabilityList, result)

		switch result.Info.Severity {
		case "critical":
			summary.Critical++
		case "high":
			summary.High++
		case "medium":
			summary.Medium++
		case "low":
			summary.Low++
		case "info":
			summary.Info++
		}
		sqlResult, _ := model.QueryVulnerability(database, result.TemplateID, result.Host)
		if sqlResult == "new" {
			log.Debug().Str("file", "main").Str("vulnerability name", result.TemplateID).Str("vulnerability host", result.Host).Msg("success")
			err = model.InsertVulnerability(database, result.TemplateID, result.Host, "open")
			if err != nil {
				log.Error().Str("file", "main").Err(err)
			}
		}
		summary.Host = result.Host
		attachmentList = append(attachmentList, createAttachment(result.Info.Name, strings.Join(result.Info.Tags, ", "), result.Info.Severity, result.Info.Classification.CvssMetrics, strconv.FormatFloat(result.Info.Classification.CvssScore, 'f', -1, 64), result.Host, result.Matched, sqlResult))
	}

	err = model.UpdateVulnerabilityStatusAll(database)
	if err != nil {
		log.Error().Str("file", "main").Err(err)
	}

	for _, vulnerability := range vulnerabilityList {
		err = model.UpdateVulnerabilityStatus(database, vulnerability.TemplateID, vulnerability.Host, "open")
		if err != nil {
			log.Error().Str("file", "main").Err(err)
		}
	}

	blockList = append(blockList, createBlock(summary))
	err = sendSlackNotification(webHookURL, attachmentList, blockList)
	if err != nil {
		log.Error().Str("file", "main").Err(err)
	}
}

//nolint:funlen
func createAttachment(name string, tags string, severity string, metric string, score string, host string, matched string, status string) (attachment model.SlackAttachmentBody) {
	nameField := model.SlackFieldBody{
		Title: "Name",
		Value: fmt.Sprintf("%s", name),
		Short: false,
	}

	tagsField := model.SlackFieldBody{
		Title: "Tags",
		Value: fmt.Sprintf("`%s`", tags),
		Short: true,
	}

	severityField := model.SlackFieldBody{
		Title: "Severity",
		Value: fmt.Sprintf("`%s`", severity),
		Short: true,
	}

	metricField := model.SlackFieldBody{
		Title: "CVSS Metric",
		Value: fmt.Sprintf("`%s - %s`", score, metric),
		Short: false,
	}

	hostField := model.SlackFieldBody{
		Title: "Host",
		Value: fmt.Sprintf("`%s`", host),
		Short: true,
	}

	statusField := model.SlackFieldBody{
		Title: "Status",
		Value: fmt.Sprintf("`%s`", status),
		Short: true,
	}

	matchedField := model.SlackFieldBody{
		Title: "Endpoint",
		Value: fmt.Sprintf("`%s`", matched),
		Short: false,
	}

	var color string
	switch {
	case severity == "critical" || severity == "high":
		color = "danger"
	case severity == "medium":
		color = "warning"
	default:
		color = "good"
	}

	var fieldList []model.SlackFieldBody
	fieldList = append(fieldList, nameField, tagsField, severityField, metricField, hostField, statusField, matchedField)

	attachment = model.SlackAttachmentBody{
		Fields: fieldList,
		Color:  color,
	}
	return attachment
}

func createBlock(summary model.SummaryReport) (block model.SlackBlockBody) {
	summaryField := model.SlackBlockFieldBody{
		Type: "mrkdwn",
		Text: fmt.Sprintf("> *Open Vulnerability Summary*, @here\n> *Host:* `%s`\n```Severity      Count\n-------------------\nCritical      %d\nHigh          %d\nMedium        %d\nLow           %d\nInfo          %d\n-------------------\nTotal         %d```", summary.Host, summary.Critical, summary.High, summary.Medium, summary.Low, summary.Info, summary.Critical+summary.High+summary.Medium+summary.Low+summary.Info),
	}

	block = model.SlackBlockBody{
		Type: "section",
		Text: summaryField,
	}
	return block
}

func sendSlackNotification(webHookURL string, attachmentList []model.SlackAttachmentBody, blockList []model.SlackBlockBody) error {
	slackMessage := model.SlackRequestBody{
		Title:       "Open Vulnerability",
		Text:        "Open Vulnerability",
		Attachments: attachmentList,
		Blocks:      blockList,
	}

	slackBody, err := json.Marshal(slackMessage)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, webHookURL, bytes.NewBuffer(slackBody))
	if err != nil {
		return err
	}

	req.Header.Add("Content-Type", "application/json")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req) //nolint:bodyclose
	if err != nil {
		return err
	}

	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(resp.Body)
	if err != nil {
		return err
	}
	log.Debug().Str("file", "main").Msg(buf.String())
	if buf.String() != "ok" {
		return errors.New("non-ok response returned from slack")
	}
	return nil
}
