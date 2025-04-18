package usecase

import (
    "context"
    "crypto/ecdsa"
    "crypto/rand"
    "encoding/hex"
    "fmt"
    "regexp"

    "github.com/btcsuite/btcd/btcec/v2"
    "github.com/hashicorp/vault/sdk/framework"
    "github.com/hashicorp/vault/sdk/logical"
)

func pathCreateAndList(b *Backend) *framework.Path {
	return &framework.Path{
		Pattern: "key-managers/?",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.createKeyManager,
			},
			logical.ListOperation: &framework.PathOperation{
				Callback: b.listKeyManagers,
			},
		},
		HelpSynopsis:    "Create or list TRON key-managers",
		HelpDescription: "POST to import or generate a TRON key; LIST to enumerate all services.",
		Fields: map[string]*framework.FieldSchema{
			"serviceName": {
				Type:        framework.TypeString,
				Description: "Identifier for the key-manager (e.g. your service name).",
			},
			"privateKey": {
				Type:        framework.TypeString,
				Description: "(Optional) Hex string of the 32-byte TRON private key. If omitted, a random key is generated.",
				Default:     "",
			},
		},
	}
}

func (b *Backend) listKeyManagers(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
	names, err := req.Storage.List(ctx, "key-managers/")
	if err != nil {
		b.Logger().Error("Failed to list key-managers", "error", err)
		return nil, err
	}
	return logical.ListResponse(names), nil
}

func (b *Backend) createKeyManager(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
	// Получаем serviceName
	serviceName, ok := data.Get("serviceName").(string)
	if !ok || serviceName == "" {
		return nil, errInvalidType
	}
	// Опциональный импорт приватного ключа
	privHexInput, ok := data.Get("privateKey").(string)
	if !ok {
		return nil, errInvalidType
	}

	// Проверяем, есть ли уже менеджер
	km, err := b.retrieveKeyManager(ctx, req, serviceName)
	if err != nil {
		return nil, err
	}
	if km == nil {
		km = &KeyManager{ServiceName: serviceName}
	}

	// 1) Импорт или генерация приватного ключа
	var privKey *ecdsa.PrivateKey
    if privHexInput != "" {
        m := regexp.MustCompile(`^[0-9a-fA-F]{64}$`).FindString(privHexInput)
        if m == "" {
            return nil, fmt.Errorf("privateKey must be 64 hex chars")
        }
        bb, err := hex.DecodeString(m)
        if err != nil {
            return nil, fmt.Errorf("invalid privateKey hex: %w", err)
        }
       secpPriv, _ := btcec.PrivKeyFromBytes(bb)
       privKey = secpPriv.ToECDSA()
    } else {
       // случайная генерация
       var err error
       privKey, err = ecdsa.GenerateKey(btcec.S256(), rand.Reader)
       if err != nil {
           return nil, fmt.Errorf("failed to generate key: %w", err)
      }
    }
	defer zeroKey(privKey)

	// 2) Собираем KeyPair
	privBytes := privKey.D.Bytes()
	secpPriv, _ := btcec.PrivKeyFromBytes(privBytes)
    pubKey := secpPriv.PubKey()               // *btcec.PublicKey
    pubBytes := pubKey.SerializeUncompressed()
    ecdsaPub := pubKey.ToECDSA()
    address := deriveTronAddress(ecdsaPub)

	kp := &KeyPair{
		PrivateKey: hex.EncodeToString(privBytes),
		PublicKey:  hex.EncodeToString(pubBytes),
		Address:    address,
	}
	km.KeyPairs = append(km.KeyPairs, kp)

	// 3) Сохраняем в Vault
	path := fmt.Sprintf("key-managers/%s", serviceName)
	entry, _ := logical.StorageEntryJSON(path, km)
	if err := req.Storage.Put(ctx, entry); err != nil {
		b.Logger().Error("Failed to store key-manager", "error", err)
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"service_name": km.ServiceName,
			"address":      kp.Address,
			"public_key":   kp.PublicKey,
		},
	}, nil
}
