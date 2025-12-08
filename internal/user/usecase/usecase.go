package usecase

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"regexp"
	"time"

	"gossip/config"
	"gossip/internal/user"
	models "gossip/internal/user/model"
	"gossip/internal/user/repository"
	"gossip/pkg/errors"
	"gossip/pkg/logger"
	"gossip/pkg/utils"

	"github.com/google/uuid"
)

type UserUsecase struct {
	repo   repository.UserRepository
	logger logger.Logger
	config config.Config
}

func NewUserUsecase(repo repository.UserRepository, logger logger.Logger, config config.Config) *UserUsecase {
	return &UserUsecase{repo: repo, logger: logger, config: config}
}

func (uc *UserUsecase) Register(ctx context.Context, cmd user.RegisterCommand) (*user.UserDTO, error) {
	if err := validateUsername(cmd.Username); err != nil {
		return nil, err
	}
	if cmd.DisplayName == "" {
		return nil, errors.InvalidArg("display name is required")
	}

	if exists, err := uc.repo.UsernameExists(ctx, cmd.Username); err != nil {
		uc.logger.Error("database error checking username", "err", err)
		return nil, errors.Internal("internal server error")
	} else if exists {
		return nil, errors.AlreadyExists("username is already taken")
	}

	identityPub, err := decodeBase64(string(cmd.IdentityKeyPublic), ed25519.PublicKeySize)
	if err != nil {
		return nil, errors.InvalidArg("invalid identity key: " + err.Error())
	}

	encryptionPub, err := decodeBase64(string(cmd.EncryptionPublicKey), 32) // X25519 is 32 bytes
	if err != nil {
		return nil, errors.InvalidArg("invalid encryption key: " + err.Error())
	}

	signedPreKeyPub, err := decodeBase64(string(cmd.SignedPreKey.PublicKey), 32)
	if err != nil {
		return nil, errors.InvalidArg("invalid signed prekey")
	}

	if !ed25519.Verify(identityPub, signedPreKeyPub, cmd.SignedPreKey.Signature) {
		return nil, errors.InvalidArg("signed prekey signature invalid")
	}

	otpkList := make([]models.OneTimePreKey, 0, len(cmd.OneTimePreKeys))
	seenKeyIDs := make(map[uint32]bool)
	for _, k := range cmd.OneTimePreKeys {
		if seenKeyIDs[k.KeyID] {
			return nil, errors.InvalidArg("duplicate one-time prekey ID")
		}
		seenKeyIDs[k.KeyID] = true

		pub, err := decodeBase64(string(k.PublicKey), 32)
		if err != nil {
			return nil, errors.InvalidArg("invalid one-time prekey")
		}
		otpkList = append(otpkList, models.OneTimePreKey{
			UserID:    uuid.Nil,
			KeyID:     k.KeyID,
			PublicKey: pub,
		})
	}

	spk := &models.SignedPreKey{
		KeyID:     cmd.SignedPreKey.KeyID,
		Signature: cmd.SignedPreKey.Signature,
		PublicKey: signedPreKeyPub,
	}
	ik := &models.IdentityKey{
		EncryptionPublicKey: encryptionPub,
		SigningPublicKey:    identityPub,
	}
	u := &models.User{
		Username: cmd.Username,
		Name:     cmd.DisplayName,
	}
	err = uc.repo.RegisterUserWithKeys(ctx, u, ik, spk, otpkList)
	if err != nil {
		uc.logger.Errorf("error while saving user in db: %v", err)
		return nil, errors.ErrRegistrationFailed(errors.Internal("database error"))
	}

	return &user.UserDTO{
		ID:          u.ID,
		Username:    u.Username,
		DisplayName: u.Name,
	}, nil
}

func decodeBase64(b64 string, expectedLen int) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	if len(data) != expectedLen {
		return nil, fmt.Errorf("expected %d bytes, got %d", expectedLen, len(data))
	}
	return data, nil
}

var usernameRegex = regexp.MustCompile(`^[a-z0-9_]{3,32}$`)

func validateUsername(username string) error {
	if !usernameRegex.MatchString(username) {
		return errors.ErrInvalidUsername
	}
	return nil
}

func (uc *UserUsecase) UpdateDisplayName(ctx context.Context, userID uuid.UUID, newName string) error {

	err := uc.repo.UpdateUserDisplayName(ctx, userID, newName)
	if err != nil {
		uc.logger.Errorf("error while updating display name in db: %v", err)
		return errors.Internal("error while updating display name in db")
	}
	return nil
}

func (uc *UserUsecase) CreateLoginChallenge(ctx context.Context, username string) (challengeID uuid.UUID,
	challenge string, expiresInSeconds int, err error) {

	user, err := uc.repo.GetUserByUsername(ctx, username)
	if err != nil {
		uc.logger.Warn("login challenge requested for unknown username", "username", username)
		return uuid.Nil, "", 0, errors.ErrUserNotFound
	}
	if user == nil {
		return uuid.Nil, "", 0, errors.ErrUserNotFound
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		uc.logger.Error("failed to generate challenge", "err", err)
		return uuid.Nil, "", 0, errors.Internal("crypto rand failed")
	}
	challenge = base64.RawStdEncoding.EncodeToString(raw) // 43 chars, URL-safe

	c := &models.LoginChallenge{
		ID:        uuid.New(),
		UserID:    user.ID,
		Challenge: challenge,
		ExpiresAt: time.Now().Add(2 * time.Minute),
		Used:      false,
	}

	if err := uc.repo.CreateLoginChallenge(ctx, c); err != nil {
		uc.logger.Error("failed to save login challenge", "err", err)
		return uuid.Nil, "", 0, errors.Internal("failed to create challenge")
	}

	return c.ID, challenge, 120, nil
}

// TODO: finish
func (uc *UserUsecase) CompleteLogin(ctx context.Context, cmd user.CompleteLoginCommand) (userWithToken *models.UserWithToken, err error) {

	//fetch challenge and user
	challenge, err := uc.repo.GetLoginChallenge(ctx, cmd.ChallengeID)
	if err != nil {
		uc.logger.Warn("challenge not found", "challenge_id", cmd.ChallengeID, "err", err)
		return nil, errors.ErrInvalidChallenge
	}
	if challenge == nil {
		return nil, errors.ErrInvalidChallenge
	}
	if challenge.Used == true {
		return nil, errors.ErrInvalidChallenge
	}
	if time.Now().After(challenge.ExpiresAt) {
		return nil, errors.ErrInvalidChallenge
	}

	user, err := uc.repo.GetUserByID(ctx, challenge.UserID)
	if err != nil || user != nil {
		return nil, errors.ErrUserNotFound
	}

	identityKey, err := uc.repo.GetIdentityKey(ctx, user.ID)
	if err != nil || identityKey == nil {
		return nil, errors.Internal("identity key missing")
	}

	//use user's publickKey to verify challenge
	ok, err := utils.ValidateChallenge(identityKey.SigningPublicKey, []byte(challenge.Challenge), cmd.Signature)
	if err != nil {
		return nil, errors.ErrInvalidSignature
	}

	//generate jwt tokens and share user with token
	token, refreshToken, err := utils.GenerateJWTToken(u, uc.config)
	if err != nil {
		return nil, errors.Internal("error while creating tokens")
	}

	return &models.UserWithToken{
		User:         u,
		Token:        token,
		RefreshToken: refreshToken,
	}, nil
}
