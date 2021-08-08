package emailer

import (
	"encoding/base64"

	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
)

type SendgridApiMail struct {
	apiKey   string
	fromName string
	from     string
}

func NewSendgridApiMail(apiKey, fromName, from string) *SendgridApiMail {
	ans := SendgridApiMail{apiKey: apiKey, fromName: fromName, from: from}
	return &ans
}

func (o *SendgridApiMail) Send(toName string, to string, subject string, content string, attachments []Attachment) error {
	m := mail.NewV3Mail()

	mailFrom := mail.NewEmail(o.fromName, o.from)
	mailContent := mail.NewContent("text/html", content)
	mailTo := mail.NewEmail(toName, to)

	m.SetFrom(mailFrom)
	m.AddContent(mailContent)

	personalization := mail.NewPersonalization()
	personalization.AddTos(mailTo)
	personalization.Subject = subject

	m.AddPersonalizations(personalization)

	toAdd := make([]*mail.Attachment, 0, len(attachments))
	for i := range attachments {
		var att mail.Attachment
		encoded := base64.StdEncoding.EncodeToString(attachments[i].Data)
		att.SetContent(encoded)
		att.SetType("text/plain")
		att.SetFilename(attachments[i].Name)
		att.SetDisposition("attachment")
		toAdd = append(toAdd, &att)
	}

	m.AddAttachment(toAdd...)
	request := sendgrid.GetRequest(o.apiKey, "/v3/mail/send", "https://api.sendgrid.com")
	request.Method = "POST"
	request.Body = mail.GetRequestBody(m)
	_, err := sendgrid.API(request)
	return err
}
