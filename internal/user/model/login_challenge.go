package models

import (
	"github.com/google/uuid"
	"time"
)

type LoginChallenge struct {
	ID     uuid.UUID `bun:",pk,type:uuid,default:gen_random_uuid()"`
	UserID uuid.UUID `bun:",notnull,type:uuid"`
	User   *User     `bun:"rel:belongs-to,join:user_id=id"`

	Challenge string    `bun:",notnull"`
	Signature []byte    `bun:",notnull"` // signed by client's Ed25519 private key
	ExpiresAt time.Time `bun:",notnull"`
	Used      bool      `bun:",default:false"`
}
