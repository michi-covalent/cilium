// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

package ingress

import (
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/sirupsen/logrus"
)

// Options stores all the configurations values for ingress controller.
type Options struct {
	Enabled    bool
	Logger     logrus.FieldLogger
	MaxRetries int
}

// DefaultOptions specifies default values for ingress controller options.
var DefaultOptions = Options{
	Enabled:    false,
	Logger:     logging.DefaultLogger.WithField(logfields.LogSubsys, Subsys),
	MaxRetries: 10,
}

// Option customizes the configuration of ingress controller.
type Option func(o *Options) error

// WithEnabled enables ingress controller.
func WithEnabled() Option {
	return func(o *Options) error {
		o.Enabled = true
		return nil
	}
}

// WithLogger sets the logger for ingress controller.
func WithLogger(logger logrus.FieldLogger) Option {
	return func(o *Options) error {
		o.Logger = logger
		return nil
	}
}

// WithMaxRetries sets the number of times ingress controller retries a given operation before
// giving up.
func WithMaxRetries(maxRetries int) Option {
	return func(o *Options) error {
		o.MaxRetries = maxRetries
		return nil
	}
}
