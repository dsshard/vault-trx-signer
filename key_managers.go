package usecase

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// KeyPair хранит пару ключей и адрес TRON
type KeyPair struct {
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
	Address    string `json:"address"`
}

// KeyManager хранит сервис‑имя и все связанные с ним ключи
type KeyManager struct {
	ServiceName string     `json:"service_name"`
	KeyPairs    []*KeyPair `json:"key_pairs"`
}

// paths возвращает список всех маршрутов плагина
func paths(b *Backend) []*framework.Path {
	return []*framework.Path{
		pathCreateAndList(b),
		pathReadAndDelete(b),
		pathSign(b),
		pathTransferTx(b),
        pathTRC20Transfer(b),  // ← в конец массива
	}
}

// retrieveKeyManager подгружает KeyManager из storage по serviceName
func (b *Backend) retrieveKeyManager(
	ctx context.Context,
	req *logical.Request,
	serviceName string,
) (*KeyManager, error) {
	path := fmt.Sprintf("key-managers/%s", serviceName)
	entry, err := req.Storage.Get(ctx, path)
	if err != nil {
		b.Logger().Error("Failed to retrieve the key-manager", "path", path, "error", err)
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var km KeyManager
	if err := entry.DecodeJSON(&km); err != nil {
		b.Logger().Error("Failed to decode key-manager JSON", "path", path, "error", err)
		return nil, err
	}
	return &km, nil
}
