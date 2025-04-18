package usecase

import (
    "context"
    "encoding/hex"
    "fmt"

    "github.com/ethereum/go-ethereum/crypto"
    "github.com/hashicorp/vault/sdk/framework"
    "github.com/hashicorp/vault/sdk/logical"
)

func pathSign(b *Backend) *framework.Path {
    return &framework.Path{
        Pattern:        "key-managers/" + framework.GenericNameRegex("name") + "/sign",
        ExistenceCheck: b.pathExistenceCheck,
        Operations: map[logical.Operation]framework.OperationHandler{
            logical.CreateOperation: &framework.PathOperation{
                Callback: b.sign,
            },
        },
        HelpSynopsis:    "Sign a SHA256 hash for TRON transaction.",
        HelpDescription: "POST name & hash (hex SHA256 rawData) → signature (hex r||s||v).",
        Fields: map[string]*framework.FieldSchema{
            "name":    {Type: framework.TypeString},
            "hash":    {Type: framework.TypeString, Description: "Hex string of 32‑byte SHA256 hash"},
        },
    }
}

func (b *Backend) sign(
    ctx context.Context,
    req *logical.Request,
    data *framework.FieldData,
) (*logical.Response, error) {
    serviceName, ok := data.Get("name").(string)
    if !ok {
        return nil, errInvalidType
    }
    hashHex, ok := data.Get("hash").(string)
    if !ok {
        return nil, errInvalidType
    }

    // 1) Получаем приватный ключ из storage
    km, err := b.retrieveKeyManager(ctx, req, serviceName)
    if err != nil || km == nil {
        return nil, fmt.Errorf("key-manager %s not found", serviceName)
    }
    privHex := km.KeyPairs[0].PrivateKey

    // 2) Конвертим hex → *ecdsa.PrivateKey
    privKey, err := crypto.HexToECDSA(privHex)
    if err != nil {
        return nil, fmt.Errorf("invalid private key hex: %w", err)
    }
    defer zeroKey(privKey)

    // 3) Декодируем SHA256‑хеш (hex)
    hashBytes, err := hex.DecodeString(hashHex)
    if err != nil {
        return nil, fmt.Errorf("invalid hash hex: %w", err)
    }

    // 4) Подписываем через go-ethereum crypto.Sign (r||s||v, 65 байт)
    sigBytes, err := crypto.Sign(hashBytes, privKey)
    if err != nil {
        return nil, fmt.Errorf("sign failed: %w", err)
    }

    return &logical.Response{
        Data: map[string]interface{}{
            "signature": hex.EncodeToString(sigBytes),
        },
    }, nil
}

