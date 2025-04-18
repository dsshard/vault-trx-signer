package usecase

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// pathReadAndDelete описывает маршруты для чтения и удаления key-manager по имени
func pathReadAndDelete(b *Backend) *framework.Path {
	return &framework.Path{
		Pattern:      "key-managers/" + framework.GenericNameRegex("name"),
		HelpSynopsis: "Get or delete a TRON key-manager by name",
		HelpDescription: `

    GET    - return the key-manager by service name
    DELETE - remove the key-manager and all its keys

    `,
		Fields: map[string]*framework.FieldSchema{
			"name": {Type: framework.TypeString},
		},
		ExistenceCheck: b.pathExistenceCheck,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.readKeyManager,
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.deleteKeyManager,
			},
		},
	}
}

// readKeyManager возвращает существующий KeyManager со списком адресов
func (b *Backend) readKeyManager(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
	serviceName, ok := data.Get("name").(string)
	if !ok {
		return nil, errInvalidType
	}

	km, err := b.retrieveKeyManager(ctx, req, serviceName)
	if err != nil {
		return nil, err
	}
	if km == nil {
		return nil, fmt.Errorf("key-manager '%s' not found", serviceName)
	}

	// Собираем список адресов
	addresses := make([]string, len(km.KeyPairs))
	for i, kp := range km.KeyPairs {
		addresses[i] = kp.Address
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"service_name": km.ServiceName,
			"addresses":    addresses,
		},
	}, nil
}

// deleteKeyManager удаляет KeyManager и все его ключи
func (b *Backend) deleteKeyManager(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
	serviceName, ok := data.Get("name").(string)
	if !ok {
		return nil, errInvalidType
	}

	km, err := b.retrieveKeyManager(ctx, req, serviceName)
	if err != nil {
		return nil, err
	}
	if km == nil {
		// Нечего удалять
		return nil, nil
	}

	path := fmt.Sprintf("key-managers/%s", serviceName)
	if err := req.Storage.Delete(ctx, path); err != nil {
		b.Logger().Error("Failed to delete key-manager", "error", err)
		return nil, err
	}

	return nil, nil
}
