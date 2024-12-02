package notifications

import (
	"github.com/containrrr/shoutrrr/pkg/router"
	"github.com/containrrr/shoutrrr/pkg/types"
	"github.com/sirupsen/logrus"
)

// Notifier handles sending notifications via Shoutrrr.
type Notifier struct {
	sr *router.ServiceRouter
}

// NewNotifier initializes a new Notifier with the provided Shoutrrr URLs.
func NewNotifier(urls []string) (*Notifier, error) {
	sr, err := router.New(nil, urls...)
	if err != nil {
		return nil, err
	}
	return &Notifier{sr: sr}, nil
}

// Send sends a notification message to all configured services.
func (n *Notifier) Send(title, message string) {
	params := types.Params{
		"title": title,
	}
	errors := n.sr.Send(message, &params)
	for _, err := range errors {
		if err != nil {
			logrus.WithError(err).Error("Failed to send notification")
		}
	}
	logrus.Info("Notification sent successfully")
}
