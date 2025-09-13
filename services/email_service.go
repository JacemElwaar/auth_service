package services

import (
	"bytes"
	"fmt"
	"html/template"

	"auth-service/config"

	"gopkg.in/gomail.v2"
)

type EmailService struct {
	config *config.Config
	dialer *gomail.Dialer
}

func NewEmailService(cfg *config.Config) *EmailService {
	dialer := gomail.NewDialer(cfg.SMTPHost, cfg.SMTPPort, cfg.SMTPUsername, cfg.SMTPPassword)
	
	// For development with MailHog, disable TLS
	if cfg.Environment == "development" && cfg.SMTPPort == 1025 {
		dialer.TLSConfig = nil
	}

	return &EmailService{
		config: cfg,
		dialer: dialer,
	}
}

func (es *EmailService) SendVerificationEmail(to, token string) error {
	verificationURL := fmt.Sprintf("%s/api/v1/verify-email?token=%s", es.config.BaseURL, token)
	
	subject := "Verify Your Email Address"
	body := fmt.Sprintf(`
		<h2>Welcome to Auth Service!</h2>
		<p>Please click the link below to verify your email address:</p>
		<p><a href="%s">Verify Email</a></p>
		<p>If you didn't create an account, you can safely ignore this email.</p>
		<p>This link will expire in 24 hours.</p>
	`, verificationURL)

	return es.sendEmail(to, subject, body)
}

func (es *EmailService) SendPasswordResetEmail(to, token string) error {
	resetURL := fmt.Sprintf("%s/reset-password?token=%s", es.config.BaseURL, token)
	
	subject := "Reset Your Password"
	body := fmt.Sprintf(`
		<h2>Password Reset Request</h2>
		<p>You requested a password reset. Click the link below to reset your password:</p>
		<p><a href="%s">Reset Password</a></p>
		<p>If you didn't request this, you can safely ignore this email.</p>
		<p>This link will expire in 1 hour.</p>
	`, resetURL)

	return es.sendEmail(to, subject, body)
}

func (es *EmailService) SendWelcomeEmail(to, name string) error {
	subject := "Welcome to Auth Service!"
	body := fmt.Sprintf(`
		<h2>Welcome %s!</h2>
		<p>Your account has been successfully created and verified.</p>
		<p>You can now log in and start using our services.</p>
		<p>If you have any questions, please don't hesitate to contact us.</p>
	`, name)

	return es.sendEmail(to, subject, body)
}

func (es *EmailService) sendEmail(to, subject, htmlBody string) error {
	m := gomail.NewMessage()
	m.SetHeader("From", es.config.SMTPFrom)
	m.SetHeader("To", to)
	m.SetHeader("Subject", subject)
	m.SetBody("text/html", htmlBody)

	return es.dialer.DialAndSend(m)
}

// EmailTemplate represents an email template
type EmailTemplate struct {
	Subject string
	Body    string
}

// LoadTemplate loads an email template (for future enhancement)
func (es *EmailService) LoadTemplate(templateName string, data interface{}) (*EmailTemplate, error) {
	// This is a placeholder for template loading functionality
	// In a real implementation, you would load templates from files
	templates := map[string]*EmailTemplate{
		"verification": {
			Subject: "Verify Your Email Address",
			Body: `
				<h2>Welcome to Auth Service!</h2>
				<p>Please click the link below to verify your email address:</p>
				<p><a href="{{.VerificationURL}}">Verify Email</a></p>
				<p>If you didn't create an account, you can safely ignore this email.</p>
				<p>This link will expire in 24 hours.</p>
			`,
		},
		"password_reset": {
			Subject: "Reset Your Password",
			Body: `
				<h2>Password Reset Request</h2>
				<p>You requested a password reset. Click the link below to reset your password:</p>
				<p><a href="{{.ResetURL}}">Reset Password</a></p>
				<p>If you didn't request this, you can safely ignore this email.</p>
				<p>This link will expire in 1 hour.</p>
			`,
		},
	}

	tmpl, exists := templates[templateName]
	if !exists {
		return nil, fmt.Errorf("template %s not found", templateName)
	}

	// Parse and execute template
	t, err := template.New(templateName).Parse(tmpl.Body)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return nil, err
	}

	return &EmailTemplate{
		Subject: tmpl.Subject,
		Body:    buf.String(),
	}, nil
}
