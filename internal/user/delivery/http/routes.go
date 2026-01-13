package delivery

import (
	"github.com/labstack/echo/v4"
	"gossip/internal/middleware"
)

func (h *UserHandler) MapUserRoutes(g *echo.Group, mw middleware.MiddlewareManager) {
	g.POST("/register", h.Register)
	g.POST("/auth/challenge", h.CreateLoginChallenge)
	g.POST("/auth/login", h.CompleteLogin)

	g.POST("/devices/prekeys", h.UploadPreKeys)
	g.GET("/users/:username/prekey-bundle", h.GetPrekeyBundleByUsername)
	g.GET("/users/:id/prekey-bundle", h.GetPreKeyBundleByUserID)

	g.GET("/users/:username", h.GetUserProfileByUsername)

	g.PATCH("/profile/display-name", h.UpdateDisplayName)
	g.GET("/users/search", h.SearchUsers)
	g.GET("/profile/me", h.GetUserProfile)

	g.GET("/devices/prekeys/remaining", h.GetRemainingOneTimePreKeys)
}
