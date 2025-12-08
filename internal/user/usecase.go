package user

import (
	"context"
	"github.com/google/uuid"
)

type UserUsecase interface {
	// Register new user with username + display name + identity key bundle
	Register(ctx context.Context, cmd RegisterCommand) (*UserDTO, error)

	// Update display name only (username is immutable)
	UpdateDisplayName(ctx context.Context, userID uuid.UUID, newName string) error

	CreateLoginChallenge(ctx context.Context, username string) (challenge string,
		challengeID uuid.UUID,
		expiresInSeconds int,
		err error)

	CompleteLogin(ctx context.Context, cmd CompleteLoginCommand) (authToken string, user *UserDTO, err error)

	// Upload/replace signed prekey + upload batch of one-time prekeys
	UploadPreKeys(ctx context.Context, userID uuid.UUID, cmd UploadPreKeysCommand) error

	// Returns everything needed for the sender to perform X3DH
	GetPreKeyBundle(ctx context.Context, targetUserID uuid.UUID) (*PreKeyBundleDTO, error)
	GetPreKeyBundleByUsername(ctx context.Context, username string) (*PreKeyBundleDTO, error)

	GetRemainingOneTimePreKeysCount(ctx context.Context, userID uuid.UUID) (int, error)
	GetUserProfile(ctx context.Context, userID uuid.UUID) (*UserProfileDTO, error)
	GetUserProfileByUsername(ctx context.Context, username string) (*UserProfileDTO, error)

	// Search users by username prefix (for @mentions, adding contacts, etc.)
	//TODO
	SearchUsers(ctx context.Context, query string, limit int) ([]*UserProfileDTO, error)
}
