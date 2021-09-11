package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
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
}

type SlackAttachmentBody struct {
	Color  string           `json:"color"`
	Fields []SlackFieldBody `json:"fields"`
}

type SlackFieldBody struct {
	Title string `json:"title"`
	Value string `json:"value"`
	Short bool   `json:"short"`
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

func main() {
	config.Set(config.LOG_LEVEL, "info")
	webHookURL := config.GetStr(config.SLACK_TOKEN)
	var attachmentList []SlackAttachmentBody

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
		attachmentList = append(attachmentList, createAttachment(result.TemplateID, result.Info.Name, result.Info.Author[0], strings.Join(result.Info.Tags, ", "), result.Info.Severity, result.Info.Classification.CvssMetrics, strconv.FormatFloat(result.Info.Classification.CvssScore, 'f', -1, 64), result.Host, result.Matched, result.IP))
	}

	err = sendSlackNotification(webHookURL, attachmentList)
	if err != nil {
		log.Error().Str("file", "main").Err(err)
	}
}

//nolint:funlen
func createAttachment(templateID string, name string, author string, tags string, severity string, metric string, score string, host string, matched string, ip string) (attachment SlackAttachmentBody) {
	templateIDField := SlackFieldBody{
		Title: "Template ID",
		Value: templateID,
		Short: true,
	}

	nameField := SlackFieldBody{
		Title: "Name",
		Value: name,
		Short: true,
	}

	authorField := SlackFieldBody{
		Title: "Author",
		Value: author,
		Short: true,
	}

	tagsField := SlackFieldBody{
		Title: "Tags",
		Value: tags,
		Short: true,
	}

	metricField := SlackFieldBody{
		Title: "CVSS Metric",
		Value: metric,
		Short: false,
	}

	scoreField := SlackFieldBody{
		Title: "CVSS Score",
		Value: score,
		Short: true,
	}

	hostField := SlackFieldBody{
		Title: "Host",
		Value: host,
		Short: true,
	}

	matchedField := SlackFieldBody{
		Title: "Matched",
		Value: matched,
		Short: false,
	}

	severityField := SlackFieldBody{
		Title: "Severity",
		Value: severity,
		Short: true,
	}

	ipField := SlackFieldBody{
		Title: "IP Address",
		Value: ip,
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
	fieldList = append(fieldList, templateIDField, nameField, authorField, tagsField, scoreField, severityField, hostField, ipField, metricField, matchedField)

	attachment = SlackAttachmentBody{
		Fields: fieldList,
		Color:  color,
	}
	return attachment
}

func sendSlackNotification(webHookURL string, attachmentList []SlackAttachmentBody) error {
	slackMessage := SlackRequestBody{
		Title:       "Penetration Testing Report - Open Vulnerability",
		Text:        "Penetration Testing Report - Open Vulnerability",
		Attachments: attachmentList,
	}

	slackBody, _ := json.Marshal(slackMessage)

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
	_, _ = buf.ReadFrom(resp.Body)
	log.Debug().Str("file", "slack").Msg(buf.String())
	if buf.String() != "ok" {
		return errors.New("non-ok response returned from slack")
	}
	return nil
}
