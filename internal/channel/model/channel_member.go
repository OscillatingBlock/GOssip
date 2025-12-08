package model

import (
	"github.com/google/uuid"
	user "gossip/internal/user/model"
	"time"
)

type ChannelMember struct {
	ChannelID uuid.UUID `bun:",pk,type:uuid"`
	Channel   *Channel  `bun:"rel:belongs-to,join:channel_id=id"`

	UserID uuid.UUID  `bun:",pk,type:uuid"`
	User   *user.User `bun:"rel:belongs-to,join:user_id=id"`

	Role string `bun:",notnull,default:'member'"` // owner, admin, member, muted, etc.

	JoinedAt   time.Time `bun:",nullzero,notnull,default:current_timestamp"`
	LastReadAt time.Time `bun:",nullzero"` // for unread count
	LastSentAt time.Time `bun:",nullzero"` // optional: for sorting

	// Permissions (optional, can be bitflag later)
	CanSendMessages bool `bun:",default:true"`
	CanInvite       bool `bun:",default:false"`
}
