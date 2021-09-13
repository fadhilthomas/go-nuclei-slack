package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/fadhilthomas/go-nuclei-slack/config"
	"github.com/rs/zerolog/log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

type SlackRequestBody struct {
	Title       string                `json:"title"`
	Text        string                `json:"text"`
	Attachments []SlackAttachmentBody `json:"attachments"`
	Blocks      []SlackBlockBody      `json:"blocks"`
}

type SlackAttachmentBody struct {
	Color  string           `json:"color"`
	Fields []SlackFieldBody `json:"fields"`
}

type SlackBlockBody struct {
	Type string              `json:"type"`
	Text SlackBlockFieldBody `json:"text"`
}

type SlackFieldBody struct {
	Title string `json:"title"`
	Value string `json:"value"`
	Short bool   `json:"short"`
}

type SlackBlockFieldBody struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type Output struct {
	TemplateID string `json:"templateID"`
	Info       struct {
		Name           string      `json:"name"`
		Author         []string    `json:"author"`
		Tags           []string    `json:"tags"`
		Reference      interface{} `json:"reference"`
		Severity       string      `json:"severity"`
		Classification struct {
			CveID       interface{} `json:"cve-id"`
			CweID       interface{} `json:"cwe-id"`
			CvssMetrics string      `json:"cvss-metrics"`
			CvssScore   float64     `json:"cvss-score"`
		} `json:"classification"`
	} `json:"info"`
	Type      string    `json:"type"`
	Host      string    `json:"host"`
	Matched   string    `json:"matched"`
	IP        string    `json:"ip"`
	Timestamp time.Time `json:"timestamp"`
}

type SummaryReport struct {
	Critical int
	High     int
	Medium   int
	Low      int
	Info     int
}

func main() {
	config.Set(config.LOG_LEVEL, "info")
	webHookURL := config.GetStr(config.SLACK_TOKEN)
	var attachmentList []SlackAttachmentBody
	var blockList []SlackBlockBody
	summary := SummaryReport{}

	file, err := os.Open(config.GetStr(config.FILE_LOCATION))
	if err != nil {
		log.Error().Str("file", "main").Err(err)
	}
	fScanner := bufio.NewScanner(file)
	for fScanner.Scan() {
		result := &Output{}
		err := json.Unmarshal([]byte(fScanner.Text()), result)
		if err != nil {
			log.Error().Str("file", "slack").Err(err)
		}

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
		attachmentList = append(attachmentList, createAttachment(result.Info.Name, strings.Join(result.Info.Tags, ", "), result.Info.Severity, result.Info.Classification.CvssMetrics, strconv.FormatFloat(result.Info.Classification.CvssScore, 'f', -1, 64), result.Host, result.Matched))
	}

	blockList = append(blockList, createBlock(summary))
	err = sendSlackNotification(webHookURL, attachmentList, blockList)
	if err != nil {
		log.Error().Str("file", "main").Err(err)
	}
}

//nolint:funlen
func createAttachment(name string, tags string, severity string, metric string, score string, host string, matched string) (attachment SlackAttachmentBody) {
	nameField := SlackFieldBody{
		Title: "Name",
		Value: fmt.Sprintf("`%s`", name),
		Short: true,
	}

	tagsField := SlackFieldBody{
		Title: "Tags",
		Value: tags,
		Short: true,
	}

	metricField := SlackFieldBody{
		Title: "CVSS Metric",
		Value: fmt.Sprintf("%s - %s", score, metric),
		Short: false,
	}

	hostField := SlackFieldBody{
		Title: "Host",
		Value: host,
		Short: true,
	}

	matchedField := SlackFieldBody{
		Title: "Endpoint",
		Value: matched,
		Short: false,
	}

	severityField := SlackFieldBody{
		Title: "Severity",
		Value: severity,
		Short: true,
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

	var fieldList []SlackFieldBody
	fieldList = append(fieldList, nameField, tagsField, severityField, hostField, metricField, matchedField)

	attachment = SlackAttachmentBody{
		Fields: fieldList,
		Color:  color,
	}
	return attachment
}

func createBlock(summary SummaryReport) (block SlackBlockBody) {
	summaryField := SlackBlockFieldBody{
		Type: "mrkdwn",
		Text: fmt.Sprintf("> *Open Vulnerability Summary*\n```Severity      Count\n-------------------\nCritical      %d\nHigh          %d\nMedium        %d\nLow           %d\nInfo          %d\n-------------------\nTotal         %d```", summary.Critical, summary.High, summary.Medium, summary.Low, summary.Info, summary.Critical+summary.High+summary.Medium+summary.Low+summary.Info),
	}

	block = SlackBlockBody{
		Type: "section",
		Text: summaryField,
	}
	return block
}

func sendSlackNotification(webHookURL string, attachmentList []SlackAttachmentBody, blockList []SlackBlockBody) error {
	slackMessage := SlackRequestBody{
		Title:       "Penetration Testing Report - Open Vulnerability",
		Text:        "Penetration Testing Report - Open Vulnerability",
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
	log.Debug().Str("file", "slack").Msg(buf.String())
	if buf.String() != "ok" {
		return errors.New("non-ok response returned from slack")
	}
	return nil
}
