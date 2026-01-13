package server

import (
	"context"
	"gossip/internal/middleware"
	delivery "gossip/internal/user/delivery/http"
	"gossip/internal/user/repository"
	"gossip/internal/user/usecase"

	"github.com/labstack/echo/v4"
)

func (s *Server) MapHandlers(e *echo.Echo) error {
	userRepo := repository.NewUserRepository(s.db, *s.Logger)
	userUsecase := usecase.NewUserUsecase(userRepo, *s.Logger, s.Config)
	userHandler := delivery.NewUserHandler(userUsecase, s.Logger, &s.Config)

	v1 := e.Group("/api/v1")
	mw := middleware.NewMiddlewareManager(s.Logger, s.Config)
	userHandler.MapUserRoutes(v1, mw)
	return nil
}

// TODO
func createTables(ctx context.Context) error {
	return nil
}
