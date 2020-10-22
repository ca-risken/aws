package main

import (
	"github.com/sirupsen/logrus"
)

var (
	appLogger = newAppLogger()
)

func newAppLogger() *logrus.Logger {
	logger := logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{})
	return logger
}
