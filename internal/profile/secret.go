package profile

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
)

// ErrMasterRequired is returned when a profile holds passwords protected by
// a master password that has not been supplied (or is wrong).
var ErrMasterRequired = errors.New("profile master password required")

// Keyring carries the secrets needed to protect proxy passwords at rest.
// A nil *Keyring is valid and simply has no master password.
type Keyring struct {
	Master string
}

var staticKey = sha256.Sum256([]byte("shunt/profile/static-key/v1"))

func seal(key, plain []byte) ([]byte, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plain, nil), nil
}

func open(key, data []byte) ([]byte, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	if len(data) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	return gcm.Open(nil, data[:gcm.NonceSize()], data[gcm.NonceSize():], nil)
}

const masterIter = 200_000

func masterKey(pw string, salt []byte) []byte {
	k, _ := pbkdf2.Key(sha256.New, pw, salt, masterIter, 32)
	return k
}

// EncryptPassword protects a password using the given mode.
func (k *Keyring) EncryptPassword(mode, plain string) (string, error) {
	if plain == "" {
		return "", nil
	}
	b64 := base64.StdEncoding.EncodeToString
	switch mode {
	case EncDisabled:
		return "plain:" + plain, nil
	case EncUser:
		ct, err := userProtect([]byte(plain))
		if err != nil {
			return "", err
		}
		return "user:" + b64(ct), nil
	case EncMaster:
		if k == nil || k.Master == "" {
			return "", ErrMasterRequired
		}
		salt := make([]byte, 16)
		if _, err := rand.Read(salt); err != nil {
			return "", err
		}
		ct, err := seal(masterKey(k.Master, salt), []byte(plain))
		if err != nil {
			return "", err
		}
		return "master:" + b64(append(salt, ct...)), nil
	default:
		ct, err := seal(staticKey[:], []byte(plain))
		if err != nil {
			return "", err
		}
		return "basic:" + b64(ct), nil
	}
}

// DecryptPassword reverses EncryptPassword.
func (k *Keyring) DecryptPassword(enc string) (string, error) {
	if enc == "" {
		return "", nil
	}
	mode, body, ok := strings.Cut(enc, ":")
	if !ok {
		return "", errors.New("malformed password field")
	}
	if mode == "plain" {
		return body, nil
	}
	raw, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		return "", err
	}
	var pt []byte
	switch mode {
	case "basic":
		pt, err = open(staticKey[:], raw)
	case "user":
		pt, err = userUnprotect(raw)
	case "master":
		if k == nil || k.Master == "" || len(raw) < 16 {
			return "", ErrMasterRequired
		}
		pt, err = open(masterKey(k.Master, raw[:16]), raw[16:])
		if err != nil {
			return "", ErrMasterRequired
		}
	default:
		return "", errors.New("unknown password encryption " + mode)
	}
	return string(pt), err
}

func (k *Keyring) encryptAll(p *Profile) error {
	for i := range p.Proxies {
		x := &p.Proxies[i]
		enc, err := k.EncryptPassword(p.Options.Encryption, x.Password)
		if err != nil {
			return err
		}
		x.PasswordEnc, x.Password, x.PasswordSet = enc, "", false
	}
	return nil
}

func (k *Keyring) decryptAll(p *Profile) error {
	var first error
	for i := range p.Proxies {
		x := &p.Proxies[i]
		if x.PasswordEnc == "" {
			continue
		}
		pw, err := k.DecryptPassword(x.PasswordEnc)
		if err != nil {
			if first == nil {
				first = err
			}
			continue
		}
		x.Password = pw
		x.PasswordEnc = ""
	}
	return first
}

// NeedsMaster reports whether any stored password requires the master password.
func (p *Profile) NeedsMaster() bool {
	for _, x := range p.Proxies {
		if strings.HasPrefix(x.PasswordEnc, "master:") {
			return true
		}
	}
	return false
}
