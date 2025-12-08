package repository

import (
	"context"
	"database/sql"

	User "gossip/internal/user/model"
	models "gossip/internal/user/model"
	"gossip/pkg/logger"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/uptrace/bun"
)

type UserRepository struct {
	db     *bun.DB
	logger *logger.Logger
}

var (
	ErrNoPreKeysAvailable = errors.New("no one-time prekeys available")
	ErrUserNotFound       = errors.New("user not found")
)

func NewUserRepository(db *bun.DB, logger logger.Logger) *UserRepository {
	return &UserRepository{
		db:     db,
		logger: &logger,
	}
}

func (r *UserRepository) CreateUser(ctx context.Context, user *User.User) error {

	_, err := r.db.NewInsert().Model(user).Returning("*").Exec(ctx)
	if err != nil {
		return errors.Wrap(err, "authRepo.CreateUser.InsertUser: ")
	}
	return nil
}

func (r *UserRepository) GetUserByID(ctx context.Context, id uuid.UUID) (*User.User, error) {

	user := new(User.User)
	err := r.db.NewSelect().Model(user).Where("id = ?", id).Scan(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "authRepo.GetUserByID.Scan: ")
	}
	return user, nil
}

func (r *UserRepository) GetUserByUsername(ctx context.Context, username string) (*User.User, error) {

	user := new(User.User)
	err := r.db.NewSelect().Model(user).Where("username = ?", username).Scan(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "authRepo.GetUserByID.Scan: ")
	}
	return user, nil
}

func (r *UserRepository) UpdateUserDisplayName(ctx context.Context, userID uuid.UUID, newName string) error {
	_, err := r.db.NewUpdate().Model((*User.User)(nil)).Set("name = ?", newName).Where("id = ?", userID).Exec(ctx)
	if err != nil {
		return errors.Wrap(err, "authRepo.UpdateUserDisplayName.Update: ")
	}
	return nil
}

func (r *UserRepository) SaveIdentityKey(ctx context.Context, key *User.IdentityKey) error {

	_, err := r.db.NewInsert().Model(key).Returning("*").Exec(ctx)
	if err != nil {
		return errors.Wrap(err, "authRepo.SaveIdentityKey.Exec: ")
	}
	return nil
}

func (r *UserRepository) GetIdentityKey(ctx context.Context, userID uuid.UUID) (*User.IdentityKey, error) {

	identityKey := new(User.IdentityKey)
	err := r.db.NewSelect().Model(identityKey).Where("user_id = ?", userID).Scan(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "authRepo.GetIdentityKey.Scan: ")
	}
	return identityKey, nil
}

func (r *UserRepository) GetIdentityKeyByUsername(ctx context.Context, username string) (*User.IdentityKey, error) {

	key := new(User.IdentityKey)
	err := r.db.NewSelect().
		Model(key).
		// 1. Use the struct field name "User". Bun automatically generates the JOIN.
		Relation("User").
		// 2. Filter using the relationship. Bun typically aliases the joined table as "user" (lowercase).
		Where("\"user\".username = ?", username).
		Scan(ctx)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, errors.Wrap(err, "authRepo.GetIdentityKey.Scan")
	}
	return key, nil
}

func (r *UserRepository) UpsertSignedPreKey(ctx context.Context, spk *User.SignedPreKey) error {
	_, err := r.db.NewInsert().
		Model(spk).
		On("CONFLICT (user_id) DO UPDATE").
		// Explicitly update the fields with the new values (EXCLUDED refers to the new data)
		Set("key_id = EXCLUDED.key_id").
		Set("public_key = EXCLUDED.public_key").
		Set("signature = EXCLUDED.signature").
		Set("uploaded_at = EXCLUDED.uploaded_at").
		Returning("*").
		Exec(ctx)

	if err != nil {
		return errors.Wrap(err, "authRepo.UpsertSignedPreKey.Exec: ")
	}
	return nil
}

func (r *UserRepository) GetSignedPreKey(ctx context.Context, userID uuid.UUID) (*User.SignedPreKey, error) {
	key := new(User.SignedPreKey)
	err := r.db.NewSelect().Model(key).Where("user_id = ?", userID).Scan(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "authRepo.GetSignedPreKey.Scan: ")
	}
	return key, nil
}

func (r *UserRepository) UploadOneTimePreKeys(ctx context.Context, userID uuid.UUID, keys []User.OneTimePreKey) error {
	_, err := r.db.NewInsert().Model(&keys).Returning("*").Exec(ctx)
	if err != nil {
		return errors.Wrap(err, "authRepo.UploadOneTimePreKeys.Insert: ")
	}
	return nil

}

func (r *UserRepository) ClaimOneTimePreKey(ctx context.Context, userID uuid.UUID) (*User.OneTimePreKey, error) {
	key := new(User.OneTimePreKey)

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	// "FOR UPDATE" tells the DB: "Don't let anyone else write to this row until I'm done"
	// "SKIP LOCKED" (Postgres only) is essentially efficient: it skips keys that are currently being claimed by others
	err = tx.NewSelect().
		Model(key).
		Where("user_id = ? AND used = ?", userID, false).
		Limit(1).
		For("UPDATE SKIP LOCKED").
		Scan(ctx)

	if err != nil && err == sql.ErrNoRows {
		return nil, errors.Wrap(err, "failed to find unused prekey")
	}

	_, err = tx.NewUpdate().
		Model(key).
		Set("used = ?", true).
		WherePK().
		Exec(ctx)

	if err != nil {
		return nil, errors.Wrap(err, "failed to mark prekey as used")
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	key.Used = true

	return key, nil
}

func (r *UserRepository) CountRemainingOneTimePreKeys(ctx context.Context, userID uuid.UUID) (int, error) {
	count, err := r.db.NewSelect().Model((*User.OneTimePreKey)(nil)).Where("used = false AND user_id = ?", userID).Count(ctx)
	if err != nil {
		return 0, errors.Wrap(err, "authRepo.CountRemainingOneTimePreKeys.Scan: ")
	}
	return count, nil
}

func (r *UserRepository) CreateLoginChallenge(ctx context.Context, challenge *User.LoginChallenge) error {
	_, err := r.db.NewInsert().Model(challenge).Returning("*").Exec(ctx)
	if err != nil {
		return errors.Wrap(err, "authRepo.CreateLoginChallenge.Insert: ")
	}
	return nil
}

func (r *UserRepository) GetLoginChallenge(ctx context.Context, challengeID uuid.UUID) (*User.LoginChallenge, error) {
	challenge := new(User.LoginChallenge)
	err := r.db.NewSelect().Model(challenge).Where("id = ?", challengeID).Scan(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "authRepo.GetLoginChallenge.Scan: ")
	}
	return challenge, nil
}

func (r *UserRepository) MarkChallengeUsed(ctx context.Context, challengeID uuid.UUID) error {
	//this is wrong way , If struct has required fields without nullzero or omitempty, Bun may try to update them too
	/* _, err := db.NewUpdate().Model(&User.LoginChallenge{Used: true}).Where("id = ?", challengeID).Exec(ctx) */

	//correct way
	_, err := r.db.NewUpdate().
		Model(&User.LoginChallenge{Used: true}).
		Column("used"). // <-- only updates this column
		Where("id = ?", challengeID).
		Exec(ctx)

	if err != nil {
		return errors.Wrap(err, "authRepo.MarkChallengeUsed.Update: ")
	}
	return nil
}

func (r *UserRepository) FetchPreKeyBundle(ctx context.Context, userID uuid.UUID) (*User.PreKeyBundle, error) {

	var bundle User.PreKeyBundle

	err := r.db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		var ik User.IdentityKey
		var spk User.SignedPreKey

		err := tx.NewSelect().Model(&ik).Where("user_id = ?", userID).Scan(ctx)
		if err != nil {
			return errors.Wrap(err, "error while getting identity key")
		}

		err = tx.NewSelect().Model(&spk).Where("user_id = ?", userID).Scan(ctx)
		if err != nil {
			return errors.New("signed prekey not found")
		}

		otpk := User.OneTimePreKey{}

		err = tx.NewSelect().
			Model(&otpk).
			Where("user_id = ? AND used = ?", userID, false).
			Limit(1).
			For("UPDATE SKIP LOCKED").
			Scan(ctx)

		if err != nil && err == sql.ErrNoRows {
			return errors.Wrap(err, "failed to find unused prekey")
		}

		_, err = tx.NewUpdate().
			Model(&otpk).
			Set("used = ?", true).
			Where("key_id = ? AND used = ?", otpk.KeyID, false).
			Exec(ctx)

		if err != nil {
			return errors.Wrap(err, "failed to mark prekey as used")
		}

		bundle.IdentityKey = ik.EncryptionPublicKey
		bundle.SignedPreKey = spk.PublicKey
		bundle.SignedPreKeyID = spk.KeyID
		bundle.SignedPreKeySig = spk.Signature
		bundle.OneTimePreKey = otpk.PublicKey
		bundle.OneTimePreKeyID = &otpk.KeyID

		return nil
	})

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}

	return &bundle, nil
}

func (r *UserRepository) FetchPreKeyBundleByUsername(ctx context.Context, username string) (*User.PreKeyBundle, error) {
	var bundle User.PreKeyBundle

	err := r.db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		var user models.User

		err := tx.NewSelect().Model(&user).Where("username = ?", username).Scan(ctx)
		userID := user.ID

		var ik User.IdentityKey
		var spk User.SignedPreKey

		err = tx.NewSelect().Model(&ik).Where("user_id = ?", userID).Scan(ctx)
		if err != nil {
			return errors.Wrap(err, "error while getting identity key")
		}

		err = tx.NewSelect().Model(&spk).Where("user_id = ?", userID).Scan(ctx)
		if err != nil {
			return errors.New("signed prekey not found")
		}

		otpk := User.OneTimePreKey{}
		err = tx.NewSelect().Model(otpk).Where("user_id = ?", userID).Where("used = false").Order("id ASC").Limit(1).Scan(ctx)

		err = tx.NewSelect().
			Model(&otpk).
			Where("user_id = ? AND used = ?", userID, false).
			Limit(1).
			For("UPDATE SKIP LOCKED").
			Scan(ctx)

		if err != nil && err == sql.ErrNoRows {
			return errors.Wrap(err, "failed to find unused prekey")
		}

		_, err = tx.NewUpdate().
			Model(&otpk).
			Set("used = ?", true).
			Where("key_id = ? AND used = ?", otpk.KeyID, false).
			Exec(ctx)

		if err != nil {
			return errors.Wrap(err, "failed to mark prekey as used")
		}

		bundle.IdentityKey = ik.EncryptionPublicKey
		bundle.SignedPreKey = spk.PublicKey
		bundle.SignedPreKeyID = spk.KeyID
		bundle.SignedPreKeySig = spk.Signature
		bundle.OneTimePreKey = otpk.PublicKey
		bundle.OneTimePreKeyID = &otpk.KeyID

		return nil
	})

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}

	return &bundle, nil
}

func (r *UserRepository) UsernameExists(ctx context.Context, username string) (bool, error) {
	user, err := r.GetUserByUsername(ctx, username)
	if err != nil {
		return false, err
	}
	if user != nil {
		return true, nil
	}
	return false, nil
}

// TODO: write tests for this
func (r *UserRepository) RegisterUserWithKeys(
	ctx context.Context,
	user *User.User,
	ik *User.IdentityKey,
	spk *User.SignedPreKey,
	otpks []User.OneTimePreKey,
) error {

	return r.db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {

		_, err := tx.NewInsert().Model(user).Returning("*").Exec(ctx)
		if err != nil {
			return errors.Wrap(err, "register.insertUser")
		}

		ik.UserID = user.ID
		spk.UserID = user.ID
		for i := range otpks {
			otpks[i].UserID = user.ID
		}

		_, err = tx.NewInsert().Model(ik).Exec(ctx)
		if err != nil {
			return errors.Wrap(err, "register.insertIdentityKey")
		}

		_, err = tx.NewInsert().Model(spk).Exec(ctx)
		if err != nil {
			return errors.Wrap(err, "register.insertSPK")
		}

		if len(otpks) > 0 {
			_, err = tx.NewInsert().Model(&otpks).Exec(ctx)
			if err != nil {
				return errors.Wrap(err, "register.insertOTPKs")
			}
		}

		return nil
	})
}

// TODO: write tests
func (r *UserRepository) CreateRefreshToken(ctx context.Context, refreshToken models.RefreshToken) error {
	_, err := r.db.NewInsert().Model(&refreshToken).Returning("*").Exec(ctx)
	if err != nil {
		return err
	}
	return nil
}

// TODO: write tests
func (r *UserRepository) GetRefreshToken(ctx context.Context, tokenID uuid.UUID) (*models.RefreshToken, error) {
	var tokenModel models.RefreshToken
	err := r.db.NewSelect().Model(&tokenModel).Where("token = ?", tokenID).Scan(ctx)
	if err != nil {
		return nil, err
	}
	return &tokenModel, nil
}
