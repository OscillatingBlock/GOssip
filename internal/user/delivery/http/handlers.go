package delivery

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"gossip/config"
	"gossip/internal/user"
	appErrors "gossip/pkg/errors"
	"gossip/pkg/logger"
	"gossip/pkg/utils"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

type UserHandler struct {
	uc     user.UserUsecase
	logger *logger.Logger
	config *config.Config
}

// shared to client
type PreKeyBundle struct {
	UserID                uuid.UUID
	IdentityKey           string
	SignedPreKeyID        uint32
	SignedPreKey          string
	SignedPreKeySignature string
	OneTimePreKeyID       *uint32
	OneTimePreKey         string
}

func NewUserHandler(uc user.UserUsecase, l *logger.Logger, c *config.Config) UserHandler {
	return UserHandler{
		uc:     uc,
		logger: l,
		config: c,
	}
}

func (h *UserHandler) Register(c echo.Context) error {
	var cmd user.RegisterCommand
	err := utils.ReadRequest(c, cmd)
	if err != nil {
		return echo.NewHTTPError(echo.ErrBadRequest.Code, echo.ErrBadRequest.Message)
	}

	cmd.IdentityKeyPublic, err = decodeB64(cmd.IdentityKeyPublic)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid identity key format")
	}

	cmd.EncryptionPublicKey, err = decodeB64(cmd.EncryptionPublicKey)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid encryption public key")
	}

	cmd.SignedPreKey.PublicKey, err = decodeB64(cmd.SignedPreKey.PublicKey)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid signed prekey")
	}

	cmd.SignedPreKey.Signature, err = decodeB64(cmd.SignedPreKey.Signature)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid signed prekey signature")
	}

	for i := range cmd.OneTimePreKeys {
		decoded, err := decodeB64(cmd.OneTimePreKeys[i].PublicKey)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("invalid one time prekey %v", i))
		}
		cmd.OneTimePreKeys[i].PublicKey = decoded
	}

	userDTO, err := h.uc.Register(c.Request().Context(), cmd)
	if err != nil {
		h.logger.Errorf("failed to register user: %w", err)
		return appErrors.MapAndSend(c, err)
	}

	return c.JSON(http.StatusCreated, userDTO)
}

func decodeB64(s []byte) ([]byte, error) {
	if len(s) == 0 {
		return nil, errors.New("empty base64 string")
	}
	return base64.StdEncoding.DecodeString(string(s))
}

func (h *UserHandler) CreateLoginChallenge(c echo.Context) error {
	type username struct {
		Username string `json:"username" validate:"required,alphanum,min=3,max=32"`
	}
	var u username
	err := utils.ReadRequest(c, u)
	if err != nil {
		return echo.NewHTTPError(echo.ErrBadRequest.Code, echo.ErrBadRequest.Message)
	}

	challenge, challengeID, expiresIN, err := h.uc.CreateLoginChallenge(c.Request().Context(), u.Username)
	if err != nil {
		h.logger.Errorf("failed to create login challenge: %w", err)
		return appErrors.MapAndSend(c, err)
	}

	return c.JSON(http.StatusOK, map[string]any{
		"challenge":   challenge,
		"challengeID": challengeID,
		"expiresIN":   expiresIN,
	})
}

func (h *UserHandler) CompleteLogin(c echo.Context) error {
	var cmd user.CompleteLoginCommand
	err := utils.ReadRequest(c, cmd)
	if err != nil {
		return echo.NewHTTPError(echo.ErrBadRequest.Code, echo.ErrBadRequest.Message)
	}
	cmd.Signature, err = decodeB64(cmd.Signature)
	if err != nil {
		h.logger.Errorf("failed to decode signature: %w", err)
		return echo.NewHTTPError(http.StatusBadRequest, "invalid signed prekey signature")
	}

	authToken, userDTO, err := h.uc.CompleteLogin(c.Request().Context(), cmd)
	if err != nil {
		h.logger.Errorf("failed to complete login: %w", err)
		return appErrors.MapAndSend(c, err)
	}
	return c.JSON(http.StatusOK, map[string]any{
		"token": authToken,
		"user":  userDTO,
	})
}

func (h *UserHandler) UpdateDisplayName(c echo.Context) error {
	userID, ok := c.Get("user_id").(uuid.UUID)
	if !ok {
		c.Logger().Infof("failed to update display name, userID not found in context")
		return appErrors.MapAndSend(c, errors.New("unauthenticated"))
	}
	type request struct {
		NewName string `json:"displayName" validate:"required,max=64"`
	}
	var cmd request
	err := utils.ReadRequest(c, cmd)
	if err != nil {
		return echo.NewHTTPError(echo.ErrBadRequest.Code, echo.ErrBadRequest.Message)
	}

	err = h.uc.UpdateDisplayName(c.Request().Context(), userID, cmd.NewName)
	if err != nil {
		c.Logger().Errorf("failed to update display name: %w", err)
		return appErrors.MapAndSend(c, err)
	}

	return c.JSON(http.StatusOK, map[string]string{"displayName": cmd.NewName})
}

func (h *UserHandler) UploadPreKeys(c echo.Context) error {
	userID, ok := c.Get("user_id").(uuid.UUID)
	if !ok {
		return appErrors.MapAndSend(c, appErrors.ErrUnauthorized)
	}

	var cmd user.UploadPreKeysCommand
	err := utils.ReadRequest(c, cmd)
	if err != nil {
		return echo.NewHTTPError(echo.ErrBadRequest.Code, echo.ErrBadRequest.Message)
	}

	cmd.SignedPreKey.PublicKey, err = decodeB64(cmd.SignedPreKey.Signature)
	if err != nil {
		c.Logger().Infof("failed to decode signed prekey: %w", err)
		return echo.NewHTTPError(echo.ErrBadRequest.Code, echo.ErrBadRequest.Message)
	}
	cmd.SignedPreKey.Signature, err = decodeB64(cmd.SignedPreKey.Signature)
	if err != nil {
		c.Logger().Infof("failed to decode signed prekey signature: %w", err)
		return echo.NewHTTPError(echo.ErrBadRequest.Code, echo.ErrBadRequest.Message)
	}

	for i := range cmd.OneTimePreKeys {
		cmd.OneTimePreKeys[i].PublicKey, err = decodeB64(cmd.OneTimePreKeys[i].PublicKey)
		if err != nil {

			c.Logger().Infof("failed to decode one time prekey: %w", err)
			return echo.NewHTTPError(echo.ErrBadRequest.Code, echo.ErrBadRequest.Message)
		}
	}

	err = h.uc.UploadPreKeys(c.Request().Context(), userID, cmd)
	if err != nil {
		h.logger.Errorf("failed to upload pre keys: %w", err)
		return appErrors.MapAndSend(c, err)
	}
	return c.JSON(http.StatusOK, map[string]any{
		"status":    "success",
		"updatedAt": time.Now().Local().Format("2026-01-11T15:04:00Z"),
	})
}

func (h *UserHandler) GetPrekeyBundleByUsername(c echo.Context) error {
	username := c.Param("username")

	dto, err := h.uc.GetPreKeyBundleByUsername(c.Request().Context(), username)
	if err != nil {
		h.logger.Errorf("failed to get PreKeyBundle by username: %w", err)
		return appErrors.MapAndSend(c, err)
	}

	var bundle PreKeyBundle
	bundle.IdentityKey = base64.StdEncoding.EncodeToString(dto.IdentityKey)
	bundle.SignedPreKey = base64.StdEncoding.EncodeToString(dto.SignedPreKey)
	bundle.SignedPreKeySignature = base64.StdEncoding.EncodeToString(dto.SignedPreKeySignature)
	if len(bundle.OneTimePreKey) != 0 {
		bundle.OneTimePreKey = base64.StdEncoding.EncodeToString(dto.OneTimePreKey)
	}

	return c.JSON(http.StatusOK, bundle)
}

func (h *UserHandler) GetPreKeyBundleByUserID(c echo.Context) error {
	targetIDString := c.Param("id")
	targetID, err := uuid.Parse(targetIDString)

	dto, err := h.uc.GetPreKeyBundle(c.Request().Context(), targetID)
	if err != nil {
		h.logger.Errorf("failed to get pre key bundle by userID: %w", err)
		return appErrors.MapAndSend(c, err)
	}

	var bundle PreKeyBundle
	bundle.IdentityKey = base64.StdEncoding.EncodeToString(dto.IdentityKey)
	bundle.SignedPreKey = base64.StdEncoding.EncodeToString(dto.SignedPreKey)
	bundle.SignedPreKeySignature = base64.StdEncoding.EncodeToString(dto.SignedPreKeySignature)
	if len(bundle.OneTimePreKey) != 0 {
		bundle.OneTimePreKey = base64.StdEncoding.EncodeToString(dto.OneTimePreKey)
	}

	return c.JSON(http.StatusOK, bundle)
}

func (h *UserHandler) GetRemainingOneTimePreKeys(c echo.Context) error {
	userID, ok := c.Get("user_id").(uuid.UUID)
	if !ok {
		h.logger.Errorf("failed to get user remaining one time pre keys, user id not found in context")
		return appErrors.MapAndSend(c, appErrors.ErrUnauthorized)
	}

	count, err := h.uc.GetRemainingOneTimePreKeysCount(c.Request().Context(), userID)
	if err != nil {
		h.logger.Errorf("failed to get remaining one time pre keys: %w", err)
		return appErrors.MapAndSend(c, err)
	}
	return c.JSON(http.StatusOK, map[string]any{
		"count": count,
	})
}

func (h *UserHandler) GetUserProfile(c echo.Context) error {
	userID, ok := c.Get("user_id").(uuid.UUID)
	if !ok {
		h.logger.Errorf("failed to get user profile, user id not found in context")
		return appErrors.MapAndSend(c, appErrors.ErrUnauthorized)
	}

	profile, err := h.uc.GetUserProfile(c.Request().Context(), userID)
	if err != nil {
		h.logger.Errorf("failed to get user profile: %w", err)
		return appErrors.MapAndSend(c, err)
	}
	return c.JSON(http.StatusOK, profile)
}

func (h *UserHandler) GetUserProfileByUsername(c echo.Context) error {
	username := c.Param("username")
	profile, err := h.uc.GetUserProfileByUsername(c.Request().Context(), username)
	if err != nil {
		h.logger.Errorf("failed to get profile by username: %w", err)
		return appErrors.MapAndSend(c, err)
	}
	return c.JSON(http.StatusOK, profile)
}

func (h *UserHandler) SearchUsers(c echo.Context) error {
	query := c.QueryParam("q")
	limitString := c.QueryParam("limit")

	limit, err := strconv.Atoi(limitString)
	if err != nil {
		h.logger.Errorf("failed to convert ascii to int : %w", err)
		return echo.NewHTTPError(echo.ErrBadRequest.Code, echo.ErrBadGateway.Message)
	}
	users, err := h.uc.SearchUsers(c.Request().Context(), query, limit)
	if err != nil {
		h.logger.Errorf("failed to search users: %w", err)
		return appErrors.MapAndSend(c, err)
	}

	return c.JSON(http.StatusOK, users)
}

func (h *UserHandler) RefreshToken(c echo.Context) error {
	type RefreshToken struct {
		token string
	}
	var refreshToken RefreshToken
	err := utils.ReadRequest(c, refreshToken)
	if err != nil {
		//TODO: bind the new jwt errors in map&send
		return appErrors.MapAndSend(c, err)
	}

	tokens, err := h.uc.RefreshToken(c.Request().Context(), refreshToken.token)
	if err != nil {
		return appErrors.MapAndSend(c, err)
	}
	return c.JSON(http.StatusOK, tokens)
}
