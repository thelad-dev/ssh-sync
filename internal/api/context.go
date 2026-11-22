package api

import "context"

type ctxKey string

const deviceIDKey ctxKey = "device_id"

func withDeviceID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, deviceIDKey, id)
}

func deviceIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(deviceIDKey).(string)
	return v
}
