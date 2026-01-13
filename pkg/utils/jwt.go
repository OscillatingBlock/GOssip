package utils

import (
	"gossip/config"
	models "gossip/internal/user/model"
	appErrors "gossip/pkg/errors"

	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type JWTClaims struct {
	ID uuid.UUID
	jwt.RegisteredClaims
}

type JWTConfig struct {
}

func GenerateJWTToken(user *models.User, config config.Config) (token string, refreshToken string, err error) {

	now := time.Now()

	accessClaims := JWTClaims{
		ID: user.ID,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Duration(config.JWT.AccessTokenExpireTime) * time.Second)),
		},
	}
	accessToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims).SignedString([]byte(config.JWT.Secret))
	if err != nil {
		return "", "", err
	}

	refreshClaims := JWTClaims{
		ID: user.ID,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Duration(config.JWT.RefreshTokenExpireTime) * time.Second)),
		},
	}
	refreshToken, err = jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims).SignedString([]byte(config.JWT.Secret))
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

func ValidateRefreshToken(refreshToken string, jwtConfig config.JWT) (*models.User, error) {
	token, err := jwt.ParseWithClaims(refreshToken, &JWTClaims{}, func(t *jwt.Token) (any, error) {
		return []byte(jwtConfig.Secret), nil
	})

	if err != nil {
		return nil, appErrors.ErrInvalidJWTToken
	}

	claims, ok := token.Claims.(*JWTClaims)
	if !ok || !token.Valid {
		return nil, appErrors.ErrInvalidJWTToken
	}

	if claims.ExpiresAt.Time.Before(time.Now()) {
		return nil, appErrors.ErrJWTExpired
	}
	user := &models.User{ID: claims.ID}
	return user, nil
}
