package user

import (
	"context"
	"github.com/google/uuid"
	User "gossip/internal/user/model"
)

type UserRepository interface {
	CreateUser(ctx context.Context, user *User.User) error
	GetUserByID(ctx context.Context, id uuid.UUID) (*User.User, error)
	GetUserByUsername(ctx context.Context, username string) (*User.User, error)
	UpdateUserDisplayName(ctx context.Context, userID uuid.UUID, newName string) error

	SaveIdentityKey(ctx context.Context, key *User.IdentityKey) error
	GetIdentityKey(ctx context.Context, userID uuid.UUID) (*User.IdentityKey, error)
	GetIdentityKeyByUsername(ctx context.Context, username string) (*User.IdentityKey, error)

	UpsertSignedPreKey(ctx context.Context, spk *User.SignedPreKey) error
	GetSignedPreKey(ctx context.Context, userID uuid.UUID) (*User.SignedPreKey, error)

	UploadOneTimePreKeys(ctx context.Context, userID uuid.UUID, keys []User.OneTimePreKey) error
	// Atomically fetch one unused OTPK and mark as used
	ClaimOneTimePreKey(ctx context.Context, userID uuid.UUID) (*User.OneTimePreKey, error)
	CountRemainingOneTimePreKeys(ctx context.Context, userID uuid.UUID) (int, error)

	CreateLoginChallenge(ctx context.Context, challenge *User.LoginChallenge) error
	GetLoginChallenge(ctx context.Context, challengeID uuid.UUID) (*User.LoginChallenge, error)
	MarkChallengeUsed(ctx context.Context, challengeID uuid.UUID) error

	// PreKey Bundle (X3DH)
	// Returns everything needed for X3DH in one atomic operation
	FetchPreKeyBundle(ctx context.Context, userID uuid.UUID) (*User.PreKeyBundle, error)
	FetchPreKeyBundleByUsername(ctx context.Context, username string) (*User.PreKeyBundle, error)
}
