package server

import (
	"gossip/config"
	"gossip/pkg/logger"

	"github.com/labstack/echo/v4"
	"github.com/uptrace/bun"
)

type Server struct {
	Config config.Config
	Logger *logger.Logger
	e      *echo.Echo
	db     *bun.DB
}

func NewServer(config config.Config, logger *logger.Logger,
	echo *echo.Echo, db *bun.DB) *Server {
	return &Server{
		Config: config,
		Logger: logger,
		e:      echo,
		db:     db,
	}
}

func (s *Server) Run() error {
	err := s.MapHandlers(s.e)
	if err != nil {
		return err
	}
	return s.e.Start(s.Config.Server.Port)
}
