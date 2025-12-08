package utils

import (
	"gossip/config"
	models "gossip/internal/user/model"
)

func GenerateJWTToken(user *models.User, config config.Config) (token, refreshToken string, err error) {
	return "", "", nil
}
