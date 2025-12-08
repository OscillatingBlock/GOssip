package repository

import (
	"context"
	"database/sql"
	"log"
	"os"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"

	"testing"

	models "gossip/internal/user/model"
	"gossip/pkg/logger"
)

var (
	testDB      *bun.DB
	pgContainer *postgres.PostgresContainer
	cleanupOnce func()
	testLogger  logger.Logger
)

func TestMain(m *testing.M) {
	ctx := context.Background()

	dbName := "gossip"
	dbUser := "aayush"
	dbPassword := "password"

	postgresContainer, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase(dbName),
		postgres.WithUsername(dbUser),
		postgres.WithPassword(dbPassword),
		postgres.BasicWaitStrategies(),
	)
	if err != nil {
		log.Printf("failed to start container: %s", err)
		return
	}

	defer func() {
		if err := pgContainer.Terminate(ctx); err != nil {
			log.Printf("failed to terminate container: %s", err)
		}
	}()

	connStr, err := postgresContainer.ConnectionString(ctx, "sslmode=disable", "application_name=test")
	if err != nil {
		log.Printf("failed to get connections string, %v", err)
	}

	connector := pgdriver.NewConnector(pgdriver.WithDSN(connStr))
	sqlDB := sql.OpenDB(connector)
	testDB = bun.NewDB(sqlDB, pgdialect.New())

	if err := sqlDB.PingContext(ctx); err != nil {
		log.Fatalf("failed to ping db: %v", err)
	}

	_, err = testDB.ExecContext(ctx, `CREATE EXTENSION IF NOT EXISTS "uuid-ossp";`)
	if err != nil {
		log.Fatalf("failed to create extension: %v", err)
	}

	tables := []any{
		(*models.User)(nil),
		(*models.IdentityKey)(nil),
		(*models.SignedPreKey)(nil),
		(*models.OneTimePreKey)(nil),
		(*models.PreKeyBundle)(nil),
		(*models.LoginChallenge)(nil),
	}

	for _, t := range tables {
		if _, err := testDB.NewCreateTable().Model(t).IfNotExists().Exec(ctx); err != nil {
			testDB.Close()
			log.Fatalf("failed to create table for %T: %v", t, err)
		}
	}

	code := m.Run()

	testDB.Close()

	os.Exit(code)
}

func Test_CreateUser(t *testing.T) {
	t.Cleanup(func() {
		_, err := testDB.ExecContext(context.Background(), `TRUNCATE TABLE users RESTART IDENTITY CASCADE`)
		require.NoError(t, err)
	})

	user := models.User{Username: "aayush", Name: "aayush"}
	repo := NewUserRepository(testDB, logger.Logger{})
	err := repo.CreateUser(context.Background(), &user)
	require.NoError(t, err)
}

func Test_GetUserByID(t *testing.T) {
	t.Cleanup(func() {
		_, err := testDB.ExecContext(context.Background(), `TRUNCATE TABLE users RESTART IDENTITY CASCADE`)
		require.NoError(t, err)

	})
	user := models.User{Username: "aayush", Name: "aayush"}
	repo := NewUserRepository(testDB, logger.Logger{})

	err := repo.CreateUser(context.Background(), &user)
	require.NoError(t, err)

	fetchedUser, err := repo.GetUserByID(context.Background(), user.ID)
	assert.Equal(t, user.Username, fetchedUser.Username)
	assert.Equal(t, user.Name, fetchedUser.Name)
	assert.NotNil(t, fetchedUser.ID)
}

func Test_GetUserByUsername(t *testing.T) {
	t.Cleanup(func() {
		_, err := testDB.ExecContext(context.Background(), `TRUNCATE TABLE users RESTART IDENTITY CASCADE`)
		require.NoError(t, err)

	})

	user := models.User{Username: "aayush", Name: "name"}
	repo := NewUserRepository(testDB, logger.Logger{})

	err := repo.CreateUser(context.Background(), &user)
	require.NoError(t, err)

	fetchedUser, err := repo.GetUserByUsername(t.Context(), user.Username)
	assert.Equal(t, user.Username, fetchedUser.Username)
	assert.Equal(t, user.Name, fetchedUser.Name)
	assert.NotNil(t, fetchedUser.ID)
}

func Test_UpdateUserDisplayName(t *testing.T) {
	t.Cleanup(func() {
		_, err := testDB.ExecContext(context.Background(), `TRUNCATE TABLE users RESTART IDENTITY CASCADE`)
		require.NoError(t, err)
	})
	user := models.User{Username: "aayush", Name: "aayush"}
	repo := NewUserRepository(testDB, logger.Logger{})

	err := repo.CreateUser(context.Background(), &user)
	require.NoError(t, err)

	err = repo.UpdateUserDisplayName(t.Context(), user.ID, "newName")
	assert.NoError(t, err)

	fetchedUser, err := repo.GetUserByID(t.Context(), user.ID)
	assert.Equal(t, "newName", fetchedUser.Name)
}

func Test_IdentityKeyfuncs(t *testing.T) {
	cleanup := func() {
		_, err := testDB.ExecContext(context.Background(), `TRUNCATE TABLE users RESTART IDENTITY CASCADE`)
		_, err = testDB.ExecContext(context.Background(), `TRUNCATE TABLE identity_keys RESTART IDENTITY CASCADE`)
		require.NoError(t, err)
	}

	user := models.User{Username: "aayush", Name: "aayush"}
	repo := NewUserRepository(testDB, logger.Logger{})

	err := repo.CreateUser(context.Background(), &user)
	require.NoError(t, err)

	signingPub := make([]byte, 32)
	encPub := make([]byte, 32)
	for i := range signingPub {
		signingPub[i] = byte(i + 1)
	}
	for i := range encPub {
		encPub[i] = byte(i + 101)
	}

	ik := &models.IdentityKey{
		UserID:              user.ID,
		SigningPublicKey:    signingPub,
		EncryptionPublicKey: encPub,
	}
	t.Run("get identity key by username", func(t *testing.T) {
		defer cleanup()

		require.NoError(t, repo.SaveIdentityKey(t.Context(), ik))
		fetchedIK, err := repo.GetIdentityKeyByUsername(t.Context(), user.Username)
		assert.NoError(t, err)

		assert.Equal(t, fetchedIK.UserID, user.ID)
		assert.Equal(t, fetchedIK.SigningPublicKey, signingPub)
		assert.Equal(t, fetchedIK.EncryptionPublicKey, encPub)
	})
	t.Run("save identity key", func(t *testing.T) {
		defer cleanup()
		require.NoError(t, repo.SaveIdentityKey(t.Context(), ik))

		var got models.IdentityKey
		err = testDB.NewSelect().
			Model(&got).
			Where("user_id = ?", user.ID).
			Limit(1).
			Scan(t.Context())
		require.NoError(t, err)

		require.Equal(t, user.ID, got.UserID)
		require.EqualValues(t, ik.SigningPublicKey, got.SigningPublicKey)
		require.EqualValues(t, ik.EncryptionPublicKey, got.EncryptionPublicKey)
		require.False(t, got.RegisteredAt.IsZero(), "registered_at should be set by DB")
	})

	t.Run("get identity key by id", func(t *testing.T) {
		defer cleanup()

		require.NoError(t, repo.SaveIdentityKey(t.Context(), ik))
		fetchedIK, err := repo.GetIdentityKey(t.Context(), user.ID)
		assert.NoError(t, err)

		assert.Equal(t, fetchedIK.UserID, user.ID)
		assert.Equal(t, fetchedIK.SigningPublicKey, signingPub)
		assert.Equal(t, fetchedIK.EncryptionPublicKey, encPub)
	})

}

func Test_SignedPreKeyFuncs(t *testing.T) {
	cleanup := func() {
		_, err := testDB.ExecContext(context.Background(), `TRUNCATE TABLE users RESTART IDENTITY CASCADE`)
		_, err = testDB.ExecContext(context.Background(), `TRUNCATE TABLE signed_pre_keys RESTART IDENTITY CASCADE`)
		require.NoError(t, err)
	}

	repo := NewUserRepository(testDB, logger.Logger{})
	get_data := func() (*models.User, *models.SignedPreKey, *models.SignedPreKey) {

		u := &models.User{
			Username: "test_upsert_spk_",
			Name:     "Test User",
		}
		require.NoError(t, repo.CreateUser(t.Context(), u))

		pub1 := make([]byte, 32)
		sig1 := make([]byte, 64)
		for i := range pub1 {
			pub1[i] = byte(i + 1)
		}
		for i := range sig1 {
			sig1[i] = byte(i + 1 + 32)
		}

		spk := &models.SignedPreKey{
			UserID:    u.ID,
			KeyID:     1,
			PublicKey: pub1,
			Signature: sig1,
		}

		pub2 := make([]byte, 32)
		sig2 := make([]byte, 64)
		for i := range pub2 {
			pub2[i] = byte(i + 101)
		}
		for i := range sig2 {
			sig2[i] = byte(i + 101 + 32)
		}

		spk2 := &models.SignedPreKey{
			UserID:     u.ID,
			KeyID:      2,
			PublicKey:  pub2,
			Signature:  sig2,
			UploadedAt: time.Now().UTC(),
		}
		return u, spk, spk2
	}

	t.Run("UpsertSignedPreKey", func(t *testing.T) {
		defer cleanup()
		u, spk, spk2 := get_data()

		require.NoError(t, repo.UpsertSignedPreKey(t.Context(), spk))

		var got1 models.SignedPreKey
		err := testDB.NewSelect().
			Model(&got1).
			Where("user_id = ?", u.ID).
			Limit(1).
			Scan(t.Context())
		require.NoError(t, err)
		require.Equal(t, uint32(1), got1.KeyID)
		require.EqualValues(t, spk.PublicKey, got1.PublicKey)
		require.EqualValues(t, spk.Signature, got1.Signature)
		require.False(t, got1.UploadedAt.IsZero(), "uploaded_at should be set by DB")

		require.NoError(t, repo.UpsertSignedPreKey(t.Context(), spk2))

		time.Sleep(100 * time.Microsecond)
		var got2 models.SignedPreKey
		err = testDB.NewSelect().
			Model(&got2).
			Where("user_id = ?", u.ID).
			Limit(1).
			Scan(t.Context())
		require.NoError(t, err)

		require.Equal(t, spk2.KeyID, got2.KeyID)
		require.EqualValues(t, spk2.PublicKey, got2.PublicKey)
		require.EqualValues(t, spk2.Signature, got2.Signature)

		require.False(t, got2.UploadedAt.IsZero())

		require.GreaterOrEqual(t, got1.UploadedAt, got2.UploadedAt, "uploaded_at should be updated")
	})

	t.Run("get signed pre key", func(t *testing.T) {
		defer cleanup()
		u, spk, _ := get_data()

		require.NoError(t, repo.UpsertSignedPreKey(t.Context(), spk))

		gotSpk, err := repo.GetSignedPreKey(t.Context(), u.ID)
		assert.NoError(t, err)

		assert.Equal(t, gotSpk.UserID, spk.UserID)
		assert.Equal(t, gotSpk.KeyID, spk.KeyID)
		assert.Equal(t, gotSpk.PublicKey, spk.PublicKey)
		assert.Equal(t, gotSpk.Signature, spk.Signature)
	})
}

func Test_OTPKeys_funcs(t *testing.T) {
	cleanup := func(t *testing.T) {
		_, err := testDB.ExecContext(context.Background(), `TRUNCATE TABLE one_time_pre_keys RESTART IDENTITY CASCADE`)
		require.NoError(t, err)
		_, err = testDB.ExecContext(context.Background(), `TRUNCATE TABLE users RESTART IDENTITY CASCADE`)
		require.NoError(t, err)
	}

	repo := NewUserRepository(testDB, logger.Logger{})

	getData := func() (models.User, []models.OneTimePreKey) {
		u := models.User{Name: "aayush", Username: "aayush"}
		assert.NoError(t, repo.CreateUser(t.Context(), &u))

		otpks := make([]models.OneTimePreKey, 10)
		for i := range otpks {
			pubKey := make([]byte, 32)
			for i := range pubKey {
				pubKey[i] = byte(i + 1)
			}
			otpks[i] = models.OneTimePreKey{
				UserID:    u.ID,
				PublicKey: pubKey,
				KeyID:     uint32(i + 1),
			}
		}

		return u, otpks
	}

	t.Run("Upload one time prekeys", func(t *testing.T) {
		defer cleanup(t)
		u, otpks := getData()

		err := repo.UploadOneTimePreKeys(t.Context(), u.ID, otpks)
		assert.NoError(t, err)

		fetchedOTPKS := make([]models.OneTimePreKey, len(otpks))
		err = repo.db.NewSelect().Model(&fetchedOTPKS).Where("user_id = ?", u.ID).Scan(t.Context())
		require.NoError(t, err)
		require.Len(t, fetchedOTPKS, len(otpks))

		for i := range otpks {
			assert.Equal(t, fetchedOTPKS[i].UserID, otpks[i].UserID)
			assert.Equal(t, fetchedOTPKS[i].KeyID, otpks[i].KeyID)
			assert.Equal(t, fetchedOTPKS[i].PublicKey, otpks[i].PublicKey)
		}
	})

	t.Run("Claim One time Prekey", func(t *testing.T) {
		defer cleanup(t)
		u, otpks := getData()

		err := repo.UploadOneTimePreKeys(t.Context(), u.ID, otpks)
		assert.NoError(t, err)

		key, err := repo.ClaimOneTimePreKey(t.Context(), u.ID)
		assert.NoError(t, err)
		assert.Equal(t, key.UserID, u.ID)
		assert.True(t, key.Used)
		assert.NotEmpty(t, key.PublicKey)
	})

	t.Run("count remaining otpks", func(t *testing.T) {
		defer cleanup(t)
		u, otpks := getData()

		err := repo.UploadOneTimePreKeys(t.Context(), u.ID, otpks)
		assert.NoError(t, err)

		key, err := repo.ClaimOneTimePreKey(t.Context(), u.ID)
		assert.NoError(t, err)
		assert.Equal(t, key.UserID, u.ID)
		assert.True(t, key.Used)
		assert.NotEmpty(t, key.PublicKey)

		key2, err := repo.ClaimOneTimePreKey(t.Context(), u.ID)
		assert.NoError(t, err)
		assert.Equal(t, key2.UserID, u.ID)
		assert.True(t, key2.Used)
		assert.NotEmpty(t, key2.PublicKey)
		assert.NotEqual(t, key.KeyID, key2.KeyID)

		count, err := repo.CountRemainingOneTimePreKeys(t.Context(), u.ID)
		assert.NoError(t, err)
		assert.Equal(t, count, len(otpks)-2)
	})
}

func Test_LoginChallenge(t *testing.T) {
	cleanup := func(t *testing.T) {
		_, err := testDB.ExecContext(context.Background(), `TRUNCATE TABLE login_challenges RESTART IDENTITY CASCADE`)
		require.NoError(t, err)
		_, err = testDB.ExecContext(context.Background(), `TRUNCATE TABLE users RESTART IDENTITY CASCADE`)
		require.NoError(t, err)
	}

	repo := NewUserRepository(testDB, logger.Logger{})

	getData := func() (*models.User, *models.LoginChallenge) {
		u := models.User{Name: "aayush", Username: "aayush"}
		assert.NoError(t, repo.CreateUser(t.Context(), &u))

		signature := make([]byte, 32)
		for i := range signature {
			signature[i] = byte(i + 1)
		}
		challenge := models.LoginChallenge{
			UserID:    u.ID,
			Challenge: "super-hard-challenge",
			Signature: signature,
			ExpiresAt: time.Now().Add(86400 * time.Second),
		}

		return &u, &challenge
	}

	t.Run("create login challenge", func(t *testing.T) {
		defer cleanup(t)
		u, challenge := getData()
		err := repo.CreateLoginChallenge(t.Context(), challenge)
		assert.NoError(t, err)

		var fetchedChallenge models.LoginChallenge
		err = repo.db.NewSelect().Model(&fetchedChallenge).Where("user_id = ?", u.ID).Scan(t.Context())

		assert.Equal(t, fetchedChallenge.ID, challenge.ID)
		assert.Equal(t, fetchedChallenge.UserID, challenge.UserID)
		assert.Equal(t, fetchedChallenge.Challenge, challenge.Challenge)
		assert.Equal(t, fetchedChallenge.Signature, challenge.Signature)
	})

	t.Run("get login challenge", func(t *testing.T) {
		defer cleanup(t)
		_, challenge := getData()
		err := repo.CreateLoginChallenge(t.Context(), challenge)
		assert.NoError(t, err)

		fetchedChallenge, err := repo.GetLoginChallenge(t.Context(), challenge.ID)
		assert.NoError(t, err)

		assert.Equal(t, fetchedChallenge.ID, challenge.ID)
		assert.Equal(t, fetchedChallenge.UserID, challenge.UserID)
		assert.Equal(t, fetchedChallenge.Challenge, challenge.Challenge)
		assert.Equal(t, fetchedChallenge.Signature, challenge.Signature)
		assert.Equal(t, fetchedChallenge.ExpiresAt, challenge.ExpiresAt)
	})

	t.Run("Mark challenge as used", func(t *testing.T) {
		defer cleanup(t)
		_, challenge := getData()
		err := repo.CreateLoginChallenge(t.Context(), challenge)
		assert.NoError(t, err)

		err = repo.MarkChallengeUsed(t.Context(), challenge.ID)
		assert.NoError(t, err)

		fetchedChallenge, err := repo.GetLoginChallenge(t.Context(), challenge.ID)
		assert.NoError(t, err)

		assert.True(t, fetchedChallenge.Used)
	})
}

func Test_PrekeyBundle(t *testing.T) {
	cleanup := func(t *testing.T) {
		_, err := testDB.ExecContext(context.Background(), `TRUNCATE TABLE identity_keys RESTART IDENTITY CASCADE`)
		require.NoError(t, err)
		_, err = testDB.ExecContext(context.Background(), `TRUNCATE TABLE users RESTART IDENTITY CASCADE`)
		require.NoError(t, err)
		_, err = testDB.ExecContext(context.Background(), `TRUNCATE TABLE signed_pre_keys RESTART IDENTITY CASCADE`)
		require.NoError(t, err)
		_, err = testDB.ExecContext(context.Background(), `TRUNCATE TABLE one_time_pre_keys RESTART IDENTITY CASCADE`)
		require.NoError(t, err)

	}

	repo := NewUserRepository(testDB, logger.Logger{})
	u := models.User{Name: "aayush", Username: "aayush"}

	getKeys := func() (models.IdentityKey, models.SignedPreKey, models.OneTimePreKey) {
		assert.NoError(t, repo.CreateUser(t.Context(), &u))

		otpks := make([]models.OneTimePreKey, 10)
		for i := range otpks {
			pubKey := make([]byte, 32)
			for i := range pubKey {
				pubKey[i] = byte(i + 1)
			}
			otpks[i] = models.OneTimePreKey{
				UserID:    u.ID,
				PublicKey: pubKey,
				KeyID:     uint32(i + 1),
			}
		}

		sig1 := make([]byte, 64)
		for i := range sig1 {
			sig1[i] = byte(i + 1 + 32)
		}

		spk := &models.SignedPreKey{
			UserID:    u.ID,
			KeyID:     1,
			PublicKey: otpks[0].PublicKey,
			Signature: sig1,
		}

		signingPub := make([]byte, 32)
		encPub := make([]byte, 32)
		for i := range signingPub {
			signingPub[i] = byte(i + 1)
		}
		for i := range encPub {
			encPub[i] = byte(i + 101)
		}

		ik := &models.IdentityKey{
			UserID:              u.ID,
			SigningPublicKey:    signingPub,
			EncryptionPublicKey: encPub,
		}

		err := repo.SaveIdentityKey(t.Context(), ik)
		assert.NoError(t, err)

		err = repo.UpsertSignedPreKey(t.Context(), spk)
		assert.NoError(t, err)

		err = repo.UploadOneTimePreKeys(t.Context(), u.ID, otpks)
		assert.NoError(t, err)

		return *ik, *spk, otpks[0]
	}

	t.Run("fetch prekey bundle", func(t *testing.T) {
		defer cleanup(t)

		ik, spk, otpk := getKeys()

		bundle, err := repo.FetchPreKeyBundle(t.Context(), u.ID)
		assert.NoError(t, err)

		assert.Equal(t, bundle.IdentityKey, ik.EncryptionPublicKey)
		assert.Equal(t, bundle.SignedPreKey, spk.PublicKey)
		assert.Equal(t, bundle.OneTimePreKey, otpk.PublicKey)
		assert.Equal(t, bundle.SignedPreKeyID, spk.KeyID)
		assert.Equal(t, bundle.SignedPreKeySig, spk.Signature)
	})

	t.Run("fetch prekey bunle using username", func(t *testing.T) {
		defer cleanup(t)

		ik, spk, otpk := getKeys()

		bundle, err := repo.FetchPreKeyBundleByUsername(t.Context(), u.Username)
		assert.NoError(t, err)

		assert.Equal(t, bundle.IdentityKey, ik.EncryptionPublicKey)
		assert.Equal(t, bundle.SignedPreKey, spk.PublicKey)
		assert.Equal(t, bundle.OneTimePreKey, otpk.PublicKey)
		assert.Equal(t, bundle.SignedPreKeyID, spk.KeyID)
		assert.Equal(t, bundle.SignedPreKeySig, spk.Signature)
	})
}
