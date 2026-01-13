package middleware

import (
	"gossip/config"
	"gossip/pkg/logger"
)

type MiddlewareManager struct {
	Logger *logger.Logger
	Config config.Config
}

func NewMiddlewareManager(logger *logger.Logger, config config.Config) MiddlewareManager {
	return MiddlewareManager{
		Logger: logger,
		Config: config,
	}
}
