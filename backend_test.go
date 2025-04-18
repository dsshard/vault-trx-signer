// internal/usecase/backend_test.go
package usecase

import (
    "context"
    "encoding/base64"
    "encoding/hex"
    "testing"

    core "github.com/fbsobreira/gotron-sdk/pkg/proto/core"
    "github.com/hashicorp/vault/sdk/logical"
    "github.com/stretchr/testify/assert"
    "google.golang.org/protobuf/proto"
)

func newTestBackend(t *testing.T) (*Backend, logical.Storage) {
    t.Helper()
    storage := &logical.InmemStorage{}
    b, err := Factory(context.Background(), &logical.BackendConfig{
        StorageView: storage,
    })
    if err != nil {
        t.Fatalf("Factory error: %v", err)
    }
    be, ok := b.(*Backend)
    if !ok {
        t.Fatalf("unexpected backend type: %T", b)
    }
    return be, storage
}

func TestCreateAndListKeyManagers(t *testing.T) {
    b, storage := newTestBackend(t)

    // 1) Import specific private key
    req := logical.TestRequest(t, logical.UpdateOperation, "key-managers")
    req.Storage = storage
    req.Data = map[string]interface{}{
        "serviceName": "svc",
        "privateKey":  "0000000000000000000000000000000000000000000000000000000000000001",
    }
    resp, err := b.HandleRequest(context.Background(), req)
    assert.NoError(t, err)
    addr1 := resp.Data["address"].(string)
    assert.Regexp(t, `^T[A-Za-z0-9]{33}$`, addr1)

    // 2) Generate second key
    req = logical.TestRequest(t, logical.UpdateOperation, "key-managers")
    req.Storage = storage
    req.Data = map[string]interface{}{"serviceName": "svc"}
    _, err = b.HandleRequest(context.Background(), req)
    assert.NoError(t, err)

    // 3) List services
    req = logical.TestRequest(t, logical.ListOperation, "key-managers")
    req.Storage = storage
    resp, err = b.HandleRequest(context.Background(), req)
    assert.NoError(t, err)
    services := resp.Data["keys"].([]string)
    assert.Equal(t, []string{"svc"}, services)

    // 4) Read service and check two addresses
    req = logical.TestRequest(t, logical.ReadOperation, "key-managers/svc")
    req.Storage = storage
    resp, err = b.HandleRequest(context.Background(), req)
    assert.NoError(t, err)
    addrs := resp.Data["addresses"].([]string)
    assert.Len(t, addrs, 2)
    assert.Contains(t, addrs, addr1)
}

func TestSignHash(t *testing.T) {
    b, storage := newTestBackend(t)

    // Create manager
    req := logical.TestRequest(t, logical.UpdateOperation, "key-managers")
    req.Storage = storage
    req.Data = map[string]interface{}{"serviceName": "svc"}
    _, err := b.HandleRequest(context.Background(), req)
    assert.NoError(t, err)

    // Get address
    req = logical.TestRequest(t, logical.ReadOperation, "key-managers/svc")
    req.Storage = storage
    resp, err := b.HandleRequest(context.Background(), req)
    assert.NoError(t, err)

    // Sign a zero‐hash
    zeroHash := hex.EncodeToString(make([]byte, 32))
    req = logical.TestRequest(t, logical.CreateOperation, "key-managers/svc/sign")
    req.Storage = storage
    req.Data = map[string]interface{}{
        "name": "svc",
        "hash": zeroHash,
    }
    resp, err = b.HandleRequest(context.Background(), req)
    assert.NoError(t, err)
    sig, _ := hex.DecodeString(resp.Data["signature"].(string))
    assert.Len(t, sig, 65)
}

func TestTransferTx(t *testing.T) {
    b, storage := newTestBackend(t)

    // Create manager
    req := logical.TestRequest(t, logical.UpdateOperation, "key-managers")
    req.Storage = storage
    req.Data = map[string]interface{}{"serviceName": "svc"}
    _, err := b.HandleRequest(context.Background(), req)
    assert.NoError(t, err)

    // Read address
    req = logical.TestRequest(t, logical.ReadOperation, "key-managers/svc")
    req.Storage = storage
    resp, err := b.HandleRequest(context.Background(), req)
    assert.NoError(t, err)
    toAddr := resp.Data["addresses"].([]string)[0]

    // Build & sign transfer
    req = logical.TestRequest(t, logical.CreateOperation, "key-managers/svc/txn/transfer")
    req.Storage = storage
    req.Data = map[string]interface{}{
        "name":     "svc",
        "to":       toAddr,
        "amount":   "1000",
        "feeLimit": 1000000,
    }
    resp, err = b.HandleRequest(context.Background(), req)
    assert.NoError(t, err)

    // Decode signed_tx
    b64 := resp.Data["signed_tx"].(string)
    bin, err := base64.StdEncoding.DecodeString(b64)
    assert.NoError(t, err)

    tx := &core.Transaction{}
    err = proto.Unmarshal(bin, tx)
    assert.NoError(t, err)

    // Проверяем контракт и подпись
    assert.Len(t, tx.RawData.Contract, 1)
    assert.Len(t, tx.Signature, 1)
    txID := resp.Data["tx_id"].(string)
    _, err = hex.DecodeString(txID)
    assert.NoError(t, err)
}
