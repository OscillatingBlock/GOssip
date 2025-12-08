package models

import (
	"github.com/google/uuid"
	"time"
)

type RefreshToken struct {
	ID        uuid.UUID `bun:",pk,type:uuid,default:gen_random_uuid()"`
	UserID    uuid.UUID `bun:",notnull,type:uuid"`
	TokenHash []byte    `bun:",notnull"`
	ExpiresAt time.Time `bun:",notnull"`
	CreatedAt time.Time `bun:",default:current_timestamp"`
	Revoked   bool      `bun:",default:false"`
}
