package emailer

type Attachment struct {
	Name string
	Data []byte
}

type Emailer interface {
	Send(toName string, to string, subject string, content string, attachments []Attachment) error
}
