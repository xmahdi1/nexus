package automation

import "context"

type inventoryGroupKey struct{}

func WithInventoryGroup(ctx context.Context, group string) context.Context {
	return context.WithValue(ctx, inventoryGroupKey{}, group)
}
func InventoryGroup(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(inventoryGroupKey{}).(string)
	return v, ok && v != ""
}
