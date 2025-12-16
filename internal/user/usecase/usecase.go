package usecase

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	e "errors"
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
	repo   user.UserRepository
	logger logger.Logger
	config config.Config
}

func NewUserUsecase(repo user.UserRepository, logger logger.Logger, config config.Config) *UserUsecase {
	return &UserUsecase{repo: repo, logger: logger, config: config}
}

func (uc *UserUsecase) Register(
	ctx context.Context,
	cmd user.RegisterCommand,
) (*user.UserDTO, error) {
	//NOTE: remember base64 decoding encoding happening in handler

	if err := validateUsername(cmd.Username); err != nil {
		return nil, errors.ErrInvalidDisplayName
	}
	if cmd.DisplayName == "" {
		return nil, errors.InvalidArg("display name is required")
	}

	exists, err := uc.repo.UsernameExists(ctx, cmd.Username)
	if err != nil {
		uc.logger.Error("database error checking username", "err", err)
		return nil, errors.Internal("internal server error")
	}
	if exists {
		return nil, errors.ErrInvalidUsername
	}

	if len(cmd.IdentityKeyPublic) != ed25519.PublicKeySize {
		return nil, errors.InvalidArg("invalid identity key length")
	}
	if len(cmd.EncryptionPublicKey) != 32 {
		return nil, errors.InvalidArg("invalid encryption key length")
	}
	if len(cmd.SignedPreKey.PublicKey) != 32 {
		return nil, errors.ErrInvalidSignedPreKey
	}
	if len(cmd.SignedPreKey.Signature) != ed25519.SignatureSize {
		return nil, errors.ErrInvalidSignedPreKey
	}

	if !ed25519.Verify(cmd.IdentityKeyPublic, cmd.SignedPreKey.PublicKey, cmd.SignedPreKey.Signature) {
		return nil, errors.ErrInvalidSignedPreKeySignature
	}

	seenKeyIDs := make(map[uint32]bool)
	otpkList := make([]models.OneTimePreKey, 0, len(cmd.OneTimePreKeys))
	for _, k := range cmd.OneTimePreKeys {
		if seenKeyIDs[k.KeyID] {
			return nil, errors.InvalidArg("duplicate one-time prekey ID")
		}
		seenKeyIDs[k.KeyID] = true

		if len(k.PublicKey) != 32 {
			return nil, errors.ErrInvalidOneTimePreKey
		}

		otpkList = append(otpkList, models.OneTimePreKey{
			KeyID:     k.KeyID,
			PublicKey: k.PublicKey,
		})
	}

	u := &models.User{
		Username: cmd.Username,
		Name:     cmd.DisplayName,
	}

	ik := &models.IdentityKey{
		SigningPublicKey:    cmd.IdentityKeyPublic,
		EncryptionPublicKey: cmd.EncryptionPublicKey,
	}

	spk := &models.SignedPreKey{
		KeyID:     cmd.SignedPreKey.KeyID,
		PublicKey: cmd.SignedPreKey.PublicKey,
		Signature: cmd.SignedPreKey.Signature,
	}

	err = uc.repo.RegisterUserWithKeys(ctx, u, ik, spk, otpkList)
	if err != nil {
		uc.logger.Error("registration failed", "username", cmd.Username, "err", err)
		return nil, errors.ErrRegistrationFailed(err)
	}

	return &user.UserDTO{
		ID:          u.ID,
		Username:    u.Username,
		DisplayName: u.Name,
	}, nil
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

// good example to understand error handling
func (uc *UserUsecase) CompleteLogin(ctx context.Context,
	cmd user.CompleteLoginCommand) (userWithToken *user.LoginResponse,
	err error) {

	//fetch challenge and user
	challenge, err := uc.repo.GetLoginChallenge(ctx, cmd.ChallengeID)
	if err != nil {
		//first check for 404
		if e.Is(err, repository.ErrLoginChallengeNotFound) {
			return nil, errors.ErrChallengeNotFound
		}
		//then invalid (400)
		uc.logger.Errorf("fetch login challenge: %v", err)
		return nil, errors.ErrInvalidChallenge
	}
	//not using Internal Error here because this is a client error
	//invalid = 400
	if challenge == nil {
		return nil, errors.ErrInvalidChallenge
	}
	if challenge.Used == true {
		return nil, errors.ErrInvalidChallenge
	}
	if time.Now().After(challenge.ExpiresAt) {
		return nil, errors.ErrInvalidChallenge
	}

	u, err := uc.repo.GetUserByID(ctx, challenge.UserID)
	if err != nil || u == nil {
		return nil, errors.ErrUserNotFound
	}

	identityKey, err := uc.repo.GetIdentityKey(ctx, u.ID)
	if err != nil || identityKey == nil {
		//why are we not returning errors.ErrIdentityKeyMissing here?
		//because if we come till this part then it means that user exists
		//and if the user exists and still there is no ik for him
		//it means we had some internal error in our system therefore
		//not returning ErrIdentityKeyMissing to client
		return nil, errors.Internal("identity key missing")
	}

	//use user's publickKey to verify challenge
	ok, err := utils.ValidateChallenge([]byte(identityKey.SigningPublicKey), []byte(challenge.Challenge), cmd.Signature)
	if err != nil || !ok {
		return nil, errors.ErrInvalidSignature
	}

	//generate jwt token and share user with token
	accessTOken, err := utils.GenerateJWTToken(u, uc.config)
	if err != nil {
		//if user provided a valid signature but we failed to create jwt token
		//this means its a server error there using internal error
		uc.logger.Error("failed to generate access token", "err", err)
		return nil, errors.Internal("error while creating tokens")
	}

	//  Mark challenge used — atomic with future refresh token save
	if err := uc.repo.MarkChallengeUsed(ctx, cmd.ChallengeID); err != nil {
		//if any error whille marking the challenge as used, then its error in our system
		//therefore using internal error
		uc.logger.Error("failed to invalidate challenge", "err", err)
		return nil, errors.Internal("login failed")
	}

	return &user.LoginResponse{
		AccessToken: accessTOken,
		ExpiresIn:   1800,
		TokenType:   "Bearer",
		User: &user.UserDTO{
			ID:          u.ID,
			Username:    u.Username,
			DisplayName: u.Name,
		},
	}, nil
}

func (uc *UserUsecase) UploadPreKeys(ctx context.Context, userID uuid.UUID,
	cmd user.UploadPreKeysCommand) error {

	user, err := uc.repo.GetUserByID(ctx, userID)
	if err != nil {
		return errors.ErrUserNotFound
	}
	identityKey, err := uc.repo.GetIdentityKey(ctx, userID)
	if err != nil || identityKey == nil {
		return errors.Internal("identity key missing")
	}

	//process spk only if provided
	if cmd.SignedPreKey != nil {
		spkPub := cmd.SignedPreKey.PublicKey
		spkSig := cmd.SignedPreKey.Signature

		signedPreKey := &models.SignedPreKey{
			UserID:    user.ID,
			KeyID:     cmd.SignedPreKey.KeyID,
			PublicKey: spkPub,
			Signature: spkSig,
		}
		if len(cmd.SignedPreKey.PublicKey) != 32 {
			return errors.ErrInvalidSignedPreKey
		}
		if len(cmd.SignedPreKey.Signature) != ed25519.SignatureSize {
			return errors.ErrInvalidSignedPreKey
		}
		//verify spk before saving
		if !ed25519.Verify(identityKey.SigningPublicKey, spkPub, spkSig) {
			return errors.ErrInvalidSignedPreKeySignature
		}

		err = uc.repo.UpsertSignedPreKey(ctx, signedPreKey)
		if err != nil {
			return errors.Wrap(errors.CodeInternal, "failed to save signed prekey", err)
		}
	}

	// Process One-Time PreKeys (if any)
	if len(cmd.OneTimePreKeys) > 0 {
		seenKeyIDs := make(map[uint32]bool)
		otpkList := make([]models.OneTimePreKey, 0, len(cmd.OneTimePreKeys))

		for i, k := range cmd.OneTimePreKeys {
			if seenKeyIDs[k.KeyID] {
				return errors.ErrInvalidOneTimePreKey
			}
			if len(k.PublicKey) != ed25519.PublicKeySize {
				return errors.ErrInvalidOneTimePreKey
			}
			seenKeyIDs[k.KeyID] = true
			pub := cmd.OneTimePreKeys[i].PublicKey
			otpkList = append(otpkList, models.OneTimePreKey{
				UserID:    userID,
				KeyID:     k.KeyID,
				PublicKey: pub,
			})
		}

		if err := uc.repo.UploadOneTimePreKeys(ctx, userID, otpkList); err != nil {
			return errors.Wrap(errors.CodeInternal, "failed to upload one-time prekeys", err)
		}
	}
	return nil
}

func (uc *UserUsecase) GetPreKeyBundle(ctx context.Context, targetUserID uuid.UUID) (*user.PreKeyBundleDTO, error) {

	preKeyBundle, err := uc.repo.FetchPreKeyBundle(ctx, targetUserID)
	if err != nil || preKeyBundle == nil {
		if e.Is(err, repository.ErrUserNotFound) || e.Is(err, repository.ErrNoPreKeysAvailable) {
			//not found (404) here, not client bad request (400)
			return nil, errors.NotFound("user or prekey bundle not available")
		}
		return nil, err
	}

	return &user.PreKeyBundleDTO{
		UserID:                targetUserID,
		IdentityKey:           preKeyBundle.IdentityKey,
		SignedPreKeyID:        preKeyBundle.SignedPreKeyID,
		SignedPreKey:          preKeyBundle.SignedPreKey,
		SignedPreKeySignature: preKeyBundle.SignedPreKeySig,
		OneTimePreKeyID:       preKeyBundle.OneTimePreKeyID,
		OneTimePreKey:         preKeyBundle.OneTimePreKey,
	}, nil
}

func (uc *UserUsecase) GetPreKeyBundleByUsername(ctx context.Context, username string) (*user.PreKeyBundleDTO, error) {

	preKeyBundle, err := uc.repo.FetchPreKeyBundleByUsername(ctx, username)

	if err != nil || preKeyBundle == nil {
		if e.Is(err, repository.ErrUserNotFound) || e.Is(err, repository.ErrNoPreKeysAvailable) {
			//not found = 404
			return nil, errors.NotFound("user or prekey bundle not available")
		}
		return nil, err
	}

	return &user.PreKeyBundleDTO{
		UserID:                preKeyBundle.UserID,
		IdentityKey:           preKeyBundle.IdentityKey,
		SignedPreKeyID:        preKeyBundle.SignedPreKeyID,
		SignedPreKey:          preKeyBundle.SignedPreKey,
		SignedPreKeySignature: preKeyBundle.SignedPreKeySig,
		OneTimePreKeyID:       preKeyBundle.OneTimePreKeyID,
		OneTimePreKey:         preKeyBundle.OneTimePreKey,
	}, nil
}

func (uc *UserUsecase) GetRemainingOneTimePreKeysCount(ctx context.Context, userID uuid.UUID) (int, error) {

	count, err := uc.repo.CountRemainingOneTimePreKeys(ctx, userID)
	if err != nil {
		uc.logger.Error("failed to count remaining one-time prekeys", "user_id", userID, "err", err)
		return 0, errors.Internal("failed to count prekeys")
	}
	return count, nil
}

func (uc *UserUsecase) GetUserProfile(ctx context.Context, userID uuid.UUID) (*user.UserProfileDTO, error) {
	u, err := uc.repo.GetUserByID(ctx, userID)
	if err != nil {
		return nil, errors.ErrUserNotFound
	}

	return &user.UserProfileDTO{
		ID:          u.ID,
		Username:    u.Username,
		DisplayName: u.Name,
	}, nil
}

func (uc *UserUsecase) GetUserProfileByUsername(ctx context.Context, username string) (*user.UserProfileDTO, error) {
	u, err := uc.repo.GetUserByUsername(ctx, username)
	if err != nil {
		return nil, errors.ErrUserNotFound
	}
	return &user.UserProfileDTO{
		ID:          u.ID,
		Username:    u.Username,
		DisplayName: u.Name,
	}, nil
}

func (uc *UserUsecase) SearchUsers(ctx context.Context, query string, limit int) ([]*user.UserProfileDTO, error) {
	if query == "" {
		return nil, errors.InvalidArg("query cannot be empty")
	}

	results, err := uc.repo.SearchUsersByUsername(ctx, query, limit)
	if err != nil {
		uc.logger.Error("user search failed", "query", query, "err", err)
		return nil, errors.Internal("search failed")
	}

	dtos := make([]*user.UserProfileDTO, len(results))
	for i, u := range results {
		dtos[i] = &user.UserProfileDTO{
			ID:          u.ID,
			Username:    u.Username,
			DisplayName: u.Name,
		}
	}
	return dtos, nil
}
