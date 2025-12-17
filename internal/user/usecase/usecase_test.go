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

	t.Run("happy path- no spk, only otpks", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockRepo := mocks.NewMockUserRepository(ctrl)

		uc := NewUserUsecase(mockRepo, *logger, cfg)
		g := mockRepo.EXPECT()

		g.GetUserByID(gomock.Any(), gomock.Any()).Return(validUser, nil)
		g.GetIdentityKey(gomock.Any(), gomock.Any()).Return(validIdentityKey, nil)
		g.UploadOneTimePreKeys(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

		newOtpksList := make([]user.OneTimePreKeyUpload, 4)
		for i := range newOtpksList {
			newOtpksList[i] = user.OneTimePreKeyUpload{
				KeyID:     uint32(i + 1000),
				PublicKey: pubKey,
			}
		}
		cmd := user.UploadPreKeysCommand{
			OneTimePreKeys: newOtpksList,
		}

		err := uc.UploadPreKeys(t.Context(), userID, cmd)
		require.NoError(t, err, "required no error")
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

		newOtpksList := make([]user.OneTimePreKeyUpload, 4)
		for i := range newOtpksList {
			newOtpksList[i] = user.OneTimePreKeyUpload{
				KeyID:     uint32(i + 1000),
				PublicKey: pubKey,
			}
		}
		newOtpksList[0].PublicKey = []byte("invalid key")
		cmd := user.UploadPreKeysCommand{
			OneTimePreKeys: newOtpksList,
		}

		err := uc.UploadPreKeys(t.Context(), userID, cmd)
		require.Error(t, err)

		assert.Equal(t, appErrors.ErrInvalidOneTimePreKey, err)
	})
}

func Test_GetPreKeyBundle(t *testing.T) {
	userID := uuid.New()

	cfg := config.Config{}
	logger, _ := logger.NewLogger(&cfg)

	t.Run("happy path- user exists", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockRepo := mocks.NewMockUserRepository(ctrl)

		uc := NewUserUsecase(mockRepo, *logger, cfg)
		g := mockRepo.EXPECT()
		otpkID := uint32(1001)

		expectedBundle := &models.PreKeyBundle{
			IdentityKey:     []byte("identity-key-32bytes................"),
			SignedPreKeyID:  1,
			SignedPreKey:    []byte("signed-prekey-32bytes..............."),
			SignedPreKeySig: []byte("signature-64bytes..................."),
			OneTimePreKeyID: &otpkID,
			OneTimePreKey:   []byte("otpk-32bytes........................"),
		}
		g.FetchPreKeyBundle(gomock.Any(), gomock.Any()).Return(expectedBundle, nil)

		dto, err := uc.GetPreKeyBundle(context.Background(), userID)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		assert.NotNil(t, dto, "expected dto ")
		assert.Equal(t, userID, dto.UserID, "expected same userID")
		assert.NotNil(t, dto.OneTimePreKeyID, "expected otpkID")
	})

	t.Run("happy path- bundle without otpk", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockRepo := mocks.NewMockUserRepository(ctrl)
		uc := NewUserUsecase(mockRepo, *logger, cfg)

		expectedBundle := &models.PreKeyBundle{
			IdentityKey:     []byte("identity-32........................."),
			SignedPreKeyID:  1,
			SignedPreKey:    []byte("spk-32.............................."),
			SignedPreKeySig: []byte("sig-64.............................."),
			OneTimePreKeyID: nil,
			OneTimePreKey:   nil,
		}

		mockRepo.EXPECT().FetchPreKeyBundle(gomock.Any(), userID).Return(expectedBundle, nil)

		dto, err := uc.GetPreKeyBundle(context.Background(), userID)
		require.NoError(t, err, "required no err")

		assert.NotNil(t, dto, "expected dto")
		assert.Nil(t, dto.OneTimePreKey, "expected nil otpk")
		assert.Nil(t, dto.OneTimePreKeyID, "expected nil otpkID")
	})

	t.Run("happy path- user not found", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockRepo := mocks.NewMockUserRepository(ctrl)
		uc := NewUserUsecase(mockRepo, *logger, cfg)

		mockRepo.EXPECT().FetchPreKeyBundle(gomock.Any(), userID).Return(nil, repository.ErrUserNotFound)

		_, err := uc.GetPreKeyBundle(context.Background(), userID)

		if !errors.Is(err, appErrors.ErrUserOrBundleNotFound) {
			t.Errorf("expected NotFound error, got %v", err)
		}
	})
}

func Test_RemainingOTPKCount(t *testing.T) {

	userID := uuid.New()
	cfg := config.Config{}
	logger, _ := logger.NewLogger(&cfg)
	count := 10

	t.Run("happy path- user exists", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockRepo := mocks.NewMockUserRepository(ctrl)

		uc := NewUserUsecase(mockRepo, *logger, cfg)
		mockRepo.EXPECT().CountRemainingOneTimePreKeys(gomock.Any(), userID).Return(10, nil)

		fetchedCount, err := uc.GetRemainingOneTimePreKeysCount(t.Context(), userID)
		require.NoError(t, err, "expected no error")
		require.Equal(t, count, fetchedCount)
	})

	t.Run("sad path- user does not exist", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockRepo := mocks.NewMockUserRepository(ctrl)

		uc := NewUserUsecase(mockRepo, *logger, cfg)
		mockRepo.EXPECT().CountRemainingOneTimePreKeys(gomock.Any(), userID).Return(0, repository.ErrUserNotFound)

		fetchedCount, err := uc.GetRemainingOneTimePreKeysCount(t.Context(), userID)
		require.Error(t, err, "expected err")
		require.Equal(t, 0, fetchedCount)
		if !errors.Is(err, appErrors.ErrUserNotFound) {
			t.Errorf("expected user not found error, got %v", err)
		}
	})
}

func Test_GetUserProfile(t *testing.T) {
	userID := uuid.New()
	user := &models.User{
		Username:  "test user",
		Name:      "testuser001",
		CreatedAt: time.Now(),
	}
	cfg := config.Config{}
	logger, _ := logger.NewLogger(&cfg)

	t.Run("happy path- user exists", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockRepo := mocks.NewMockUserRepository(ctrl)

		uc := NewUserUsecase(mockRepo, *logger, cfg)
		mockRepo.EXPECT().GetUserByID(gomock.Any(), userID).Return(user, nil)

		u, err := uc.GetUserProfile(t.Context(), userID)
		require.NoError(t, err)
		assert.Equal(t, user.ID, u.ID)
		assert.Equal(t, user.Username, u.Username)
		assert.Equal(t, user.Name, u.DisplayName)
	})

	t.Run("sad path- user does not exists", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockRepo := mocks.NewMockUserRepository(ctrl)

		uc := NewUserUsecase(mockRepo, *logger, cfg)
		mockRepo.EXPECT().GetUserByID(gomock.Any(), userID).Return(nil, repository.ErrUserNotFound)

		u, err := uc.GetUserProfile(t.Context(), userID)
		require.Error(t, err, "expcted error")

		if !errors.Is(err, appErrors.ErrUserNotFound) {
			t.Errorf("expected invalid user id error, got %v", err)
		}
		assert.Nil(t, u, "expected nil")
	})
}

func Test_GetUserProfileByUsername(t *testing.T) {
	userID := uuid.New()
	user := &models.User{
		ID:        userID,
		Username:  "testuser001",
		Name:      "test User",
		CreatedAt: time.Now(),
	}
	cfg := config.Config{}
	logger, _ := logger.NewLogger(&cfg)

	t.Run("happy path- user exists", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockRepo := mocks.NewMockUserRepository(ctrl)

		uc := NewUserUsecase(mockRepo, *logger, cfg)
		mockRepo.EXPECT().GetUserByUsername(gomock.Any(), user.Username).Return(user, nil)

		u, err := uc.GetUserProfileByUsername(t.Context(), user.Username)
		require.NoError(t, err)
		assert.Equal(t, user.ID, u.ID)
		assert.Equal(t, user.Username, u.Username)
		assert.Equal(t, user.Name, u.DisplayName)
	})

	t.Run("sad path- user does not exists", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockRepo := mocks.NewMockUserRepository(ctrl)

		uc := NewUserUsecase(mockRepo, *logger, cfg)
		mockRepo.EXPECT().GetUserByUsername(gomock.Any(), user.Username).Return(nil, repository.ErrUserNotFound)

		u, err := uc.GetUserProfileByUsername(t.Context(), user.Username)
		require.Error(t, err, "expcted error")

		if !errors.Is(err, appErrors.ErrUserNotFound) {
			t.Errorf("expected invalid user id error, got %v", err)
		}
		assert.Nil(t, u, "expected nil")
	})
}
func TestUserUsecase_SearchUsers(t *testing.T) {
	user1ID := uuid.New()
	user2ID := uuid.New()

	mockUsers := []*models.User{
		{
			ID:       user1ID,
			Username: "alice",
			Name:     "Alice Wonder",
		},
		{
			ID:       user2ID,
			Username: "alicia",
			Name:     "Alicia Keys",
		},
	}

	cfg := config.Config{}
	l, _ := logger.NewLogger(&cfg)
	t.Run("happy path - returns matching users", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockRepo := mocks.NewMockUserRepository(ctrl)

		uc := &UserUsecase{
			repo: mockRepo,
		}

		mockRepo.EXPECT().
			SearchUsersByUsername(gomock.Any(), "ali", 20).
			Return(mockUsers, nil)

		dtos, err := uc.SearchUsers(context.Background(), "ali", 20)

		require.NoError(t, err)
		require.Len(t, dtos, 2)

		require.Equal(t, user1ID, dtos[0].ID)
		require.Equal(t, "alice", dtos[0].Username)
		require.Equal(t, "Alice Wonder", dtos[0].DisplayName)

		require.Equal(t, user2ID, dtos[1].ID)
		require.Equal(t, "alicia", dtos[1].Username)
		require.Equal(t, "Alicia Keys", dtos[1].DisplayName)
	})

	t.Run("happy path - no results returns empty slice", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockRepo := mocks.NewMockUserRepository(ctrl)
		uc := &UserUsecase{repo: mockRepo}

		mockRepo.EXPECT().
			SearchUsersByUsername(gomock.Any(), "nonexistent", 20).
			Return([]*models.User{}, nil)

		dtos, err := uc.SearchUsers(context.Background(), "nonexistent", 20)

		require.NoError(t, err)
		require.Empty(t, dtos)
	})

	t.Run("sad path - empty query", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockRepo := mocks.NewMockUserRepository(ctrl)
		uc := &UserUsecase{repo: mockRepo}

		dtos, err := uc.SearchUsers(context.Background(), "", 20)

		require.Error(t, err)
		require.Nil(t, dtos)
		require.True(t, errors.Is(err, appErrors.ErrInvalidQuery))
	})

	t.Run("sad path - repository error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockRepo := mocks.NewMockUserRepository(ctrl)
		uc := &UserUsecase{repo: mockRepo, logger: *l}

		mockRepo.EXPECT().
			SearchUsersByUsername(gomock.Any(), "ali", 20).
			Return(nil, errors.New("db down"))

		_, err := uc.SearchUsers(context.Background(), "ali", 20)

		require.Error(t, err)
	})

	t.Run("applies default and max limit", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockRepo := mocks.NewMockUserRepository(ctrl)
		uc := &UserUsecase{repo: mockRepo}

		mockRepo.EXPECT().
			SearchUsersByUsername(gomock.Any(), "a", 20).
			Return(mockUsers, nil)
		mockRepo.EXPECT().
			SearchUsersByUsername(gomock.Any(), "a", 100).
			Return(mockUsers, nil)

		_, err := uc.SearchUsers(context.Background(), "a", 0)
		require.NoError(t, err)
		_, err = uc.SearchUsers(context.Background(), "a", 200)
		require.NoError(t, err)
	})
}
