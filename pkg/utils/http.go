package utils

import "github.com/labstack/echo/v4"

func ReadRequest(ctx echo.Context, request any) error {
	if err := ctx.Bind(request); err != nil {
		return err
	}
	return validate.StructCtx(ctx.Request().Context(), request)
}
