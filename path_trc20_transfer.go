// internal/usecase/path_trc20_transfer.go

package usecase

import (
    "context"
    "crypto/sha256"
    "encoding/base64"
    "encoding/hex"
    "fmt"
    "math/big"
    "strings"
    "time"

    "github.com/ethereum/go-ethereum/accounts/abi"
    "github.com/ethereum/go-ethereum/common"
    "github.com/ethereum/go-ethereum/crypto"
    core "github.com/fbsobreira/gotron-sdk/pkg/proto/core"
    "github.com/hashicorp/vault/sdk/framework"
    "github.com/hashicorp/vault/sdk/logical"
    "google.golang.org/protobuf/proto"
    "google.golang.org/protobuf/types/known/anypb"
)

func pathTRC20Transfer(b *Backend) *framework.Path {
    return &framework.Path{
        Pattern:        "key-managers/" + framework.GenericNameRegex("name") + "/txn/trc20/transfer",
        ExistenceCheck: b.pathExistenceCheck,
        Operations: map[logical.Operation]framework.OperationHandler{
            logical.CreateOperation: &framework.PathOperation{Callback: b.transferTRC20},
        },
        HelpSynopsis:    "Build & sign a TRC‑20 token transfer.",
        HelpDescription: "POST name, contract, to, amount, feeLimit → signed_tx (base64), tx_id (hex).",
        Fields: map[string]*framework.FieldSchema{
            "name":     {Type: framework.TypeString},
            "contract": {Type: framework.TypeString},
            "to":       {Type: framework.TypeString},
            "amount":   {Type: framework.TypeString},
            "feeLimit": {Type: framework.TypeInt, Default: 1000000},
        },
    }
}

func (b *Backend) transferTRC20(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
    // 1) Извлечь приватный ключ
    name := data.Get("name").(string)
    km, err := b.retrieveKeyManager(ctx, req, name)
    if err != nil || km == nil {
        return nil, fmt.Errorf("key-manager %s not found", name)
    }
    privHex := km.KeyPairs[0].PrivateKey
    privKey, err := crypto.HexToECDSA(privHex)
    if err != nil {
        return nil, fmt.Errorf("invalid private key: %w", err)
    }
    defer zeroKey(privKey)

    // 2) Подготовить адреса и сумму
    ownerAddrBytes := decodeBase58(km.KeyPairs[0].Address)
    contractAddrBytes := decodeBase58(data.Get("contract").(string))
    toAddrBytes := decodeBase58(data.Get("to").(string))

    amtStr := data.Get("amount").(string)
    amount, ok := new(big.Int).SetString(amtStr, 10)
    if !ok {
        return nil, fmt.Errorf("invalid amount: %s", amtStr)
    }

    // 3) ABI‑кодируем вызов transfer(address,uint256)
    abiJSON := `[{"constant":false,"inputs":[{"name":"to","type":"address"},{"name":"value","type":"uint256"}],"name":"transfer","outputs":[{"name":"","type":"bool"}],"type":"function"}]`
    parsedABI, err := abi.JSON(strings.NewReader(abiJSON))
    if err != nil {
        return nil, fmt.Errorf("failed to parse ERC-20 ABI: %w", err)
    }
    // Передаём common.Address, а не []byte
    toAddr := common.BytesToAddress(toAddrBytes)
    payload, err := parsedABI.Pack("transfer", toAddr, amount)
    if err != nil {
        return nil, fmt.Errorf("ABI pack failed: %w", err)
    }

    // 4) Собираем TriggerSmartContract
    tr := &core.TriggerSmartContract{
        OwnerAddress:    ownerAddrBytes,
        ContractAddress: contractAddrBytes,
        Data:            payload,
        CallValue:       0,
    }
    anyParam, err := anypb.New(tr)
    if err != nil {
        return nil, fmt.Errorf("wrap contract: %w", err)
    }

    feeLimit := int64(data.Get("feeLimit").(int))
    raw := &core.TransactionRaw{
        Contract: []*core.Transaction_Contract{{
            Type:      core.Transaction_Contract_TriggerSmartContract,
            Parameter: anyParam,
        }},
        Timestamp:  time.Now().UnixNano() / 1e6,
        Expiration: time.Now().Add(10 * time.Minute).UnixNano() / 1e6,
        FeeLimit:   feeLimit,
    }
    tx := &core.Transaction{RawData: raw}

    // 5) Подписываем rawData
    rawBytes, err := proto.Marshal(raw)
    if err != nil {
        return nil, fmt.Errorf("marshal rawData: %w", err)
    }
    hash := sha256.Sum256(rawBytes)
    sig, err := crypto.Sign(hash[:], privKey)
    if err != nil {
        return nil, fmt.Errorf("sign failed: %w", err)
    }
    tx.Signature = [][]byte{sig}

    // 6) Сериализуем полную транзакцию и возвращаем
    fullTx, err := proto.Marshal(tx)
    if err != nil {
        return nil, fmt.Errorf("marshal full tx: %w", err)
    }
    signedB64 := base64.StdEncoding.EncodeToString(fullTx)
    txID := sha256.Sum256(rawBytes)

    return &logical.Response{
        Data: map[string]interface{}{
            "signed_tx": signedB64,
            "tx_id":     hex.EncodeToString(txID[:]),
        },
    }, nil
}
