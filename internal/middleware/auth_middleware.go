package middleware

import (
	"context"
	"strings"

	"gossip/config"
	appErrors "gossip/pkg/errors"
	"gossip/pkg/utils"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

func (mw *MiddlewareManager) AuthJWTMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		bearerHeader := c.Request().Header.Get("Authorization")
		if bearerHeader != "" {
			headerParts := strings.Split(bearerHeader, " ")
			if len(headerParts) != 2 {
				mw.Logger.Error("len headerParts != 2")
				return appErrors.ErrInvalidJWTToken
			}

			tokenString := headerParts[1]
			err := mw.ValidateJWTToken(tokenString, mw.Config, c)
			if err != nil {
				return err
			}
			return next(c)
		}
		return next(c)
	}
}

func (mw MiddlewareManager) ValidateJWTToken(tokenString string, cfg config.Config, c echo.Context) error {
	if tokenString == "" {
		return appErrors.ErrInvalidJWTToken
	}
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, appErrors.ErrInvalidTokenSigningMethod
		}
		secret := []byte(cfg.JWT.Secret)
		return secret, nil
	})
	if err != nil {
		return err
	}

	if !token.Valid {
		return appErrors.ErrInvalidJWTToken
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		userID, ok := claims["id"].(string)
		if !ok {
			return appErrors.ErrJWTInvalidClaims
		}

		userUUID, err := uuid.Parse(userID)
		if err != nil {
			return err
		}

		jwtClaims := &utils.JWTClaims{
			ID: userUUID,
		}
		ctx := context.WithValue(c.Request().Context(), "claims", jwtClaims)
		c.SetRequest(c.Request().WithContext(ctx))
	}
	return nil
}
