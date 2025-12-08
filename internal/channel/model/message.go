package model

import (
	"github.com/google/uuid"
	user "gossip/internal/user/model"
	"time"
)

type ChannelMessage struct {
	ID        uuid.UUID `bun:",pk,type:uuid,default:gen_random_uuid()"`
	ChannelID uuid.UUID `bun:",notnull,type:uuid"`
	Channel   *Channel  `bun:"rel:belongs-to,join:channel_id=id"`

	SenderID uuid.UUID  `bun:",notnull,type:uuid"`
	Sender   *user.User `bun:"rel:belongs-to,join:sender_id=id"`

	Content     string `bun:",null"` // remove when full E2EE
	Ciphertext  []byte `bun:",null"` // future group E2EE
	MessageType string `bun:",notnull,default:'text'"`

	SentAt    time.Time  `bun:",nullzero,notnull,default:current_timestamp"`
	EditedAt  *time.Time `bun:",nullzero"`
	DeletedAt *time.Time `bun:",soft_delete"`
}
