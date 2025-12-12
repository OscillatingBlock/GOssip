package models

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID uuid.UUID `bun:",pk,type:uuid,default:gen_random_uuid()"`

	// Username = unique @handle (used for login and identity)
	Username string `bun:",unique,notnull"`

	// Name = display name shown in chats (can be changed freely)
	Name string `bun:",notnull"`

	CreatedAt time.Time `bun:",nullzero,notnull,default:current_timestamp"`
	UpdatedAt time.Time `bun:",nullzero,notnull,default:current_timestamp"`
}

type PreKeyBundle struct {
	UserID          uuid.UUID
	IdentityKey     []byte
	SignedPreKey    []byte
	SignedPreKeyID  uint32
	SignedPreKeySig []byte
	OneTimePreKey   []byte
	OneTimePreKeyID *uint32
}

type UserWithToken struct {
	User         *User
	Token        string
	RefreshToken string
}
