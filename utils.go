package usecase

import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/sha256"
    "errors"
    "math/big"
    "regexp"

    "golang.org/x/crypto/sha3"
    "github.com/btcsuite/btcd/btcec/v2"
    "github.com/btcsuite/btcutil/base58"
)

var (
    errInvalidType = errors.New("invalid input type")
)

// zeroKey обнуляет private key D
func zeroKey(k *ecdsa.PrivateKey) {
    b := k.D.Bits()
    for i := range b {
        b[i] = 0
    }
}

// validNumber парсит decimal строку в *big.Int
func validNumber(input string) *big.Int {
    if input == "" {
        return big.NewInt(0)
    }
    matched, _ := regexp.MatchString(`^\d+$`, input)
    if !matched {
        return nil
    }
    num := new(big.Int)
    num, ok := num.SetString(input, 10)
    if !ok {
        return nil
    }
    return num
}

// decodeBase58 декодирует Base58Check‑строку, отбрасывает версию+checksum
func decodeBase58(addr string) []byte {
    full := base58.Decode(addr)
    if len(full) < 5 {
        return nil
    }
    return full[1 : len(full)-4]
}

// deriveTronAddress берет ecdsa.PublicKey и возвращает
// Tron‑адрес (Base58Check, версия 0x41)
func deriveTronAddress(pub *ecdsa.PublicKey) string {
    // 1) Сериализуем uncompressed pubkey: 0x04||X||Y
    raw := elliptic.Marshal(btcec.S256(), pub.X, pub.Y)
    // 2) Keccak256(X||Y) и берём последние 20 байт
    h := sha3.NewLegacyKeccak256()
    h.Write(raw[1:])
    addrHash := h.Sum(nil)[12:]
    // 3) Добавляем версию 0x41 и считаем двойной SHA256 checksum
    versioned := append([]byte{0x41}, addrHash...)
    // 4) Двойной SHA256 для контрольной суммы
    cs1 := sha256.Sum256(versioned)
    cs2 := sha256.Sum256(cs1[:])
    // 5) Финальный байтовый массив = versioned || cs2[0:4]
    full := append(versioned, cs2[0:4]...)
    // 4) Base58Encode
    return base58.Encode(full)
}

// contains проверяет, есть ли в массиве *big.Int значение value
func contains(arr []*big.Int, value *big.Int) bool {
   for _, a := range arr {
       if a.Cmp(value) == 0 {
           return true
       }
   }
   return false
}