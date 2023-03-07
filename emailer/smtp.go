package emailer

import (
	"crypto/tls"
	"fmt"
	mail "github.com/xhit/go-simple-mail/v2"
	"strings"
	"time"
)

type SmtpMail struct {
	hostname   string
	port       int
	username   string
	password   string
	authType   mail.AuthType
	encryption mail.Encryption
	noTLSCheck bool
	fromName   string
	from       string
}

func authType(authType string) mail.AuthType {
	switch strings.ToUpper(authType) {
	case "PLAIN":
		return mail.AuthPlain
	case "LOGIN":
		return mail.AuthLogin
	default:
		return mail.AuthNone
	}
}

func encryptionType(encryptionType string) mail.Encryption {
	switch strings.ToUpper(encryptionType) {
	case "NONE":
		return mail.EncryptionNone
	case "SSL":
		return mail.EncryptionSSL
	case "SSLTLS":
		return mail.EncryptionSSLTLS
	case "TLS":
		return mail.EncryptionTLS
	default:
		return mail.EncryptionSTARTTLS
	}
}

func NewSmtpMail(hostname string, port int, username string, password string, noTLSCheck bool, auth string, fromName, from string, encryption string) *SmtpMail {
	ans := SmtpMail{hostname: hostname, port: port, username: username, password: password, noTLSCheck: noTLSCheck, fromName: fromName, from: from, authType: authType(auth), encryption: encryptionType(encryption)}
	return &ans
}

func addressField(address string, name string) string {
	if name == "" {
		return address
	}
	return fmt.Sprintf("%s <%s>", name, address)
}

func (o *SmtpMail) Send(toName string, to string, subject string, content string, attachments []Attachment) error {
	server := mail.NewSMTPClient()

	server.Host = o.hostname
	server.Port = o.port
	server.Authentication = o.authType
	server.Username = o.username
	server.Password = o.password
	server.Encryption = o.encryption
	server.KeepAlive = false
	server.ConnectTimeout = 10 * time.Second
	server.SendTimeout = 10 * time.Second

	if o.noTLSCheck {
		server.TLSConfig = &tls.Config{InsecureSkipVerify: true}
	}

	smtpClient, err := server.Connect()

	if err != nil {
		return err
	}

	email := mail.NewMSG()
	email.SetFrom(addressField(o.from, o.fromName)).
		AddTo(addressField(to, toName)).
		SetSubject(subject).
		SetBody(mail.TextHTML, content)

	for _, v := range attachments {
		email.Attach(&mail.File{Name: v.Name, Data: v.Data})
	}

	err = email.Send(smtpClient)

	return err
}
