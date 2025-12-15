package usecase

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"gossip/config"
	"gossip/internal/user"
	"gossip/internal/user/mocks"
	models "gossip/internal/user/model"
	"gossip/internal/user/repository"
	appErrors "gossip/pkg/errors"
	"gossip/pkg/logger"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUserUsecase_CompleteLogin(t *testing.T) {
	challengeID := uuid.New()
	userID := uuid.New()
	pubKey, privKey, _ := ed25519.GenerateKey(nil)
	challengeStr := "test-challenge"
	validSignature := ed25519.Sign(privKey, []byte(challengeStr))
	invalidSignature := []byte("wrong-signature")

	validChallenge := &models.LoginChallenge{
		ID:        challengeID,
		UserID:    userID,
		Challenge: challengeStr,
		ExpiresAt: time.Now().Add(time.Minute),
		Used:      false,
	}

	validUser := &models.User{
		ID:       userID,
		Username: "testuser",
		Name:     "Test User",
	}

	validIdentityKey := &models.IdentityKey{
		UserID:           userID,
		SigningPublicKey: pubKey,
	}
	cfg := config.Config{}

	t.Run("happy path - successful login", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockRepo := mocks.NewMockUserRepository(ctrl)

		logger, _ := logger.NewLogger(&cfg)
		uc := &UserUsecase{
			repo:   mockRepo,
			logger: *logger,
		}

		g := mockRepo.EXPECT()
		g.GetLoginChallenge(gomock.Any(), challengeID).Return(validChallenge, nil)
		g.GetUserByID(gomock.Any(), userID).Return(validUser, nil)
		g.GetIdentityKey(gomock.Any(), userID).Return(validIdentityKey, nil)
		g.MarkChallengeUsed(gomock.Any(), challengeID).Return(nil)

		cmd := user.CompleteLoginCommand{
			ChallengeID: challengeID,
			Signature:   validSignature,
		}

		resp, err := uc.CompleteLogin(context.Background(), cmd)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if resp.AccessToken == "" {
			t.Error("expected non-empty access token")
		}
		if resp.User == nil || resp.User.ID != userID {
			t.Error("expected user in response")
		}
	})

	t.Run("sad path - challenge not found", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockRepo := mocks.NewMockUserRepository(ctrl)

		logger, _ := logger.NewLogger(&cfg)
		uc := &UserUsecase{
			repo:   mockRepo,
			logger: *logger,
		}

		mockRepo.EXPECT().
			GetLoginChallenge(gomock.Any(), challengeID).
			Return(nil, repository.ErrLoginChallengeNotFound)

		cmd := user.CompleteLoginCommand{
			ChallengeID: challengeID,
			Signature:   validSignature,
		}

		_, err := uc.CompleteLogin(context.Background(), cmd)
		if !errors.Is(err, appErrors.ErrChallengeNotFound) {
			t.Errorf("expected ErrInvalidChallenge, got %v", err)
		}
	})

	t.Run("sad path - expired challenge", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockRepo := mocks.NewMockUserRepository(ctrl)
		uc := &UserUsecase{repo: mockRepo}

		expiredChallenge := &models.LoginChallenge{
			ID:        challengeID,
			UserID:    userID,
			Challenge: challengeStr,
			ExpiresAt: time.Now().Add(-time.Minute), // expired
			Used:      false,
		}

		mockRepo.EXPECT().
			GetLoginChallenge(gomock.Any(), challengeID).
			Return(expiredChallenge, nil)

		cmd := user.CompleteLoginCommand{
			ChallengeID: challengeID,
			Signature:   validSignature,
		}

		_, err := uc.CompleteLogin(context.Background(), cmd)
		if !errors.Is(err, appErrors.ErrInvalidChallenge) {
			t.Errorf("expected ErrInvalidChallenge, got %v", err)
		}
	})

	t.Run("sad path - invalid signature", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockRepo := mocks.NewMockUserRepository(ctrl)
		uc := &UserUsecase{repo: mockRepo}

		g := mockRepo.EXPECT()
		g.GetLoginChallenge(gomock.Any(), challengeID).Return(validChallenge, nil)
		g.GetUserByID(gomock.Any(), userID).Return(validUser, nil)
		g.GetIdentityKey(gomock.Any(), userID).Return(validIdentityKey, nil)

		cmd := user.CompleteLoginCommand{
			ChallengeID: challengeID,
			Signature:   invalidSignature,
		}

		_, err := uc.CompleteLogin(context.Background(), cmd)
		if !errors.Is(err, appErrors.ErrInvalidSignature) {
			t.Errorf("expected ErrInvalidSignature, got %v", err)
		}
	})

}

func Test_Register(t *testing.T) {
	userID := uuid.New()
	pubKey, privKey, _ := ed25519.GenerateKey(nil)

	validUser := &models.User{
		ID:        userID,
		Username:  "testuser",
		Name:      "Test User",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	validIdentityKey := &models.IdentityKey{
		SigningPublicKey:    pubKey,
		EncryptionPublicKey: pubKey,
	}

	signedPreKeyPub := pubKey
	signature := ed25519.Sign(privKey, signedPreKeyPub)

	validPreKey := &user.SignedPreKeyUpload{
		KeyID:     uuid.New().ID(),
		PublicKey: signedPreKeyPub,
		Signature: signature,
	}

	otpksList := make([]user.OneTimePreKeyUpload, 4)
	for i := range otpksList {
		otpksList[i] = user.OneTimePreKeyUpload{
			KeyID:     uint32(i + 1000),
			PublicKey: pubKey,
		}
	}

	cmd := user.RegisterCommand{
		Username:            validUser.Username,
		DisplayName:         validUser.Name,
		IdentityKeyPublic:   validIdentityKey.SigningPublicKey,
		EncryptionPublicKey: validIdentityKey.EncryptionPublicKey,
		SignedPreKey:        *validPreKey,
		OneTimePreKeys:      otpksList,
	}
	cfg := config.Config{}
	logger, _ := logger.NewLogger(&cfg)

	t.Run("happy path- valid user", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockRepo := mocks.NewMockUserRepository(ctrl)

		uc := NewUserUsecase(mockRepo, *logger, cfg)

		g := mockRepo.EXPECT()
		g.UsernameExists(context.Background(), validUser.Username).Return(false, nil)
		g.RegisterUserWithKeys(context.Background(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Return(nil)

		userDTO, err := uc.Register(context.Background(), cmd)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if userDTO == nil {
			t.Fatalf("expected userDTO, got nil")
		}
		assert.NotNil(t, userDTO.ID)
		assert.NotNil(t, userDTO.Username)
		assert.NotNil(t, userDTO.DisplayName)
		assert.Equal(t, userDTO.Username, validUser.Username)
		assert.Equal(t, userDTO.DisplayName, validUser.Name)
	})

	t.Run("sad path- invalid user, username exists", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockRepo := mocks.NewMockUserRepository(ctrl)

		uc := NewUserUsecase(mockRepo, *logger, cfg)
		g := mockRepo.EXPECT()
		g.UsernameExists(context.Background(), validUser.Username).Return(true, nil)

		userDTO, err := uc.Register(context.Background(), cmd)
		if err == nil {
			t.Fatalf("expected error")
		}
		assert.Equal(t, err, appErrors.ErrInvalidUsername)
		assert.Nil(t, userDTO)
	})

	t.Run("sad path- invalid user, invalid identity key length", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockRepo := mocks.NewMockUserRepository(ctrl)

		uc := NewUserUsecase(mockRepo, *logger, cfg)
		g := mockRepo.EXPECT()
		g.UsernameExists(context.Background(), validUser.Username).Return(false, nil)

		invalidCmd := cmd
		invalidCmd.IdentityKeyPublic = []byte("invalid public key")

		userDTO, err := uc.Register(context.Background(), invalidCmd)
		if err == nil {
			t.Fatalf("expected error")
		}
		assert.Equal(t, err, appErrors.InvalidArg("invalid identity key length"))
		assert.Nil(t, userDTO)
	})

	t.Run("sad path- invaid user, invalid signed prekey signature length", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockRepo := mocks.NewMockUserRepository(ctrl)

		uc := NewUserUsecase(mockRepo, *logger, cfg)
		g := mockRepo.EXPECT()
		g.UsernameExists(context.Background(), validUser.Username).Return(false, nil)

		invalidCmd := cmd
		invalidCmd.SignedPreKey.Signature = []byte("invalid signature key")

		userDTO, err := uc.Register(context.Background(), invalidCmd)
		if err == nil {
			t.Fatalf("expected error")
		}
		assert.Equal(t, err, appErrors.ErrInvalidSignedPreKey)
		assert.Nil(t, userDTO)
	})

	t.Run("sad path- invaid user, invalid signed prekey signature", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockRepo := mocks.NewMockUserRepository(ctrl)

		uc := NewUserUsecase(mockRepo, *logger, cfg)
		g := mockRepo.EXPECT()
		g.UsernameExists(context.Background(), validUser.Username).Return(false, nil)

		invalidCmd := cmd
		anotherPubKey, _, _ := ed25519.GenerateKey(nil)
		invalidCmd.SignedPreKey.PublicKey = anotherPubKey

		userDTO, err := uc.Register(context.Background(), invalidCmd)
		if err == nil {
			t.Fatalf("expected error")
		}
		assert.Equal(t, err, appErrors.ErrInvalidSignedPreKeySignature)
		assert.Nil(t, userDTO)
	})

	t.Run("sad path- db down", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockRepo := mocks.NewMockUserRepository(ctrl)

		uc := NewUserUsecase(mockRepo, *logger, cfg)
		g := mockRepo.EXPECT()
		g.UsernameExists(context.Background(), validUser.Username).Return(false, errors.New("db down"))

		userDTO, err := uc.Register(context.Background(), cmd)
		if err == nil {
			t.Fatalf("expected error")
		}
		assert.Equal(t, err, appErrors.Internal("internal server error"))
		assert.Nil(t, userDTO)
	})
}

func Test_CreateLoginChallenge(t *testing.T) {
	userID := uuid.New()

	validUser := &models.User{
		ID:       userID,
		Username: "testuser",
		Name:     "Test User",
	}

	cfg := config.Config{}
	logger, _ := logger.NewLogger(&cfg)

	t.Run("happy path- valid user", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockRepo := mocks.NewMockUserRepository(ctrl)

		uc := NewUserUsecase(mockRepo, *logger, cfg)
		g := mockRepo.EXPECT()

		g.GetUserByUsername(gomock.Any(), gomock.Any()).Return(validUser, nil)
		g.CreateLoginChallenge(gomock.Any(), gomock.Any()).Return(nil)

		cID, challenge, expiresIN, err := uc.CreateLoginChallenge(t.Context(), validUser.Name)
		require.NoError(t, err)
		assert.Equal(t, expiresIN, 120)
		assert.NotNil(t, challenge)
		assert.NotNil(t, cID)
	})

	t.Run("invalid User", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockRepo := mocks.NewMockUserRepository(ctrl)

		uc := NewUserUsecase(mockRepo, *logger, cfg)
		g := mockRepo.EXPECT()

		g.GetUserByUsername(gomock.Any(), gomock.Any()).Return(nil, repository.ErrUserNotFound)
		cID, challenge, _, err := uc.CreateLoginChallenge(t.Context(), validUser.Name)
		require.Error(t, err)
		assert.Equal(t, err, appErrors.ErrUserNotFound)
		assert.Equal(t, challenge, "")
		assert.IsType(t, uuid.Nil, cID)
	})
}

func Test_UploadPreKeys(t *testing.T) {

	userID := uuid.New()
	pubKey, privKey, _ := ed25519.GenerateKey(nil)

	validUser := &models.User{
		ID:        userID,
		Username:  "testuser",
		Name:      "Test User",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	validIdentityKey := &models.IdentityKey{
		SigningPublicKey:    pubKey,
		EncryptionPublicKey: pubKey,
	}

	signedPreKeyPub := pubKey
	signature := ed25519.Sign(privKey, signedPreKeyPub)

	validSignedPreKey := &user.SignedPreKeyUpload{
		KeyID:     uuid.New().ID(),
		PublicKey: signedPreKeyPub,
		Signature: signature,
	}

	otpksList := make([]user.OneTimePreKeyUpload, 4)
	for i := range otpksList {
		otpksList[i] = user.OneTimePreKeyUpload{
			KeyID:     uint32(i + 1000),
			PublicKey: pubKey,
		}
	}

	cmd := user.UploadPreKeysCommand{
		SignedPreKey:   validSignedPreKey,
		OneTimePreKeys: otpksList,
	}

	cfg := config.Config{}
	logger, _ := logger.NewLogger(&cfg)

	t.Run("happy path- valid spk and otpks", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockRepo := mocks.NewMockUserRepository(ctrl)

		uc := NewUserUsecase(mockRepo, *logger, cfg)
		g := mockRepo.EXPECT()

		g.GetUserByID(gomock.Any(), gomock.Any()).Return(validUser, nil)
		g.GetIdentityKey(gomock.Any(), gomock.Any()).Return(validIdentityKey, nil)
		g.UpsertSignedPreKey(gomock.Any(), gomock.Any()).Return(nil)
		g.UploadOneTimePreKeys(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

		err := uc.UploadPreKeys(t.Context(), userID, cmd)
		require.NoError(t, err)
	})

	t.Run("sad path- invalid spk signature", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockRepo := mocks.NewMockUserRepository(ctrl)

		uc := NewUserUsecase(mockRepo, *logger, cfg)
		g := mockRepo.EXPECT()

		invalidCmd := cmd
		anotherPubKey, _, _ := ed25519.GenerateKey(nil)
		invalidCmd.SignedPreKey.PublicKey = anotherPubKey

		g.GetUserByID(gomock.Any(), gomock.Any()).Return(validUser, nil)
		g.GetIdentityKey(gomock.Any(), gomock.Any()).Return(validIdentityKey, nil)

		err := uc.UploadPreKeys(t.Context(), userID, invalidCmd)
		require.Error(t, err)
		assert.Equal(t, err, appErrors.ErrInvalidSignedPreKeySignature)
	})

	t.Run("sad path- inalid otpksList", func(t *testing.T) {

		ctrl := gomock.NewController(t)
		mockRepo := mocks.NewMockUserRepository(ctrl)

		uc := NewUserUsecase(mockRepo, *logger, cfg)
		g := mockRepo.EXPECT()

		g.GetUserByID(gomock.Any(), gomock.Any()).Return(validUser, nil)
		g.GetIdentityKey(gomock.Any(), gomock.Any()).Return(validIdentityKey, nil)
		g.UpsertSignedPreKey(gomock.Any(), gomock.Any()).Return(nil)

		invalidCmd := cmd
		invalidCmd.OneTimePreKeys[0].PublicKey = []byte("invalid key")
		err := uc.UploadPreKeys(t.Context(), userID, invalidCmd)
		require.Error(t, err)

		assert.Equal(t, appErrors.ErrInvalidOneTimePreKey, err)
	})
}
