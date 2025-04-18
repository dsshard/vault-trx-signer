package usecase

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// Backend реализует TRON‑секрет‑энджин
type Backend struct {
	*framework.Backend
}

// Factory создаёт и настраивает backend
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

// backend прописывает общие настройки плагина
func backend() *Backend {
	var b Backend
	b.Backend = &framework.Backend{
		Help: "Vault TRON Signer plugin: хранит ключи и подписывает транзакции TRX",
		Paths: framework.PathAppend(
			paths(&b), // сюда добавятся ваши pathCreateAndList, pathSign, pathTransfer и т.п.
		),
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{"key-managers/"},
		},
		Secrets:     []*framework.Secret{},
		BackendType: logical.TypeLogical,
	}
	return &b
}

// pathExistenceCheck проверяет, есть ли запись по данному пути
func (b *Backend) pathExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	entry, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		b.Logger().Error("Path existence failed", "error", err)
		return false, fmt.Errorf("existence check failed: %w", err)
	}
	return entry != nil, nil
}
