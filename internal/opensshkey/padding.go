// Package opensshkey repariert unverschlüsselte OpenSSH-Private-Keys (openssh-key-v1).
package opensshkey

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

const (
	pemBegin = "-----BEGIN OPENSSH PRIVATE KEY-----"
	pemEnd   = "-----END OPENSSH PRIVATE KEY-----"
	magic    = "openssh-key-v1\x00"
)

// FixPadding korrigiert das Private-Block-Padding (Bytes 1..N auf 8-Byte-Grenze).
// Betrifft u. a. Keys aus dem Web-Keygen mit doppeltem Padding.
// Unveränderte Keys: changed=false, Rückgabe ist eine Kopie von pem.
func FixPadding(pem []byte) (fixed []byte, changed bool, err error) {
	body, ok := extractPEMBody(pem)
	if !ok {
		return nil, false, errors.New("kein OpenSSH-Private-Key-PEM")
	}
	raw, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		return nil, false, fmt.Errorf("base64: %w", err)
	}
	if !bytes.HasPrefix(raw, []byte(magic)) {
		return nil, false, errors.New("kein openssh-key-v1")
	}

	rest := raw[len(magic):]
	cipherName, rest, err := readString(rest)
	if err != nil {
		return nil, false, err
	}
	kdfName, rest, err := readString(rest)
	if err != nil {
		return nil, false, err
	}
	kdfOpts, rest, err := readString(rest)
	if err != nil {
		return nil, false, err
	}
	if string(cipherName) != "none" || string(kdfName) != "none" {
		return nil, false, fmt.Errorf("verschlüsselter Key (%s/%s) — Padding nicht reparierbar ohne Passphrase", cipherName, kdfName)
	}

	if len(rest) < 4 {
		return nil, false, errors.New("nkeys fehlt")
	}
	nkeys := binary.BigEndian.Uint32(rest[:4])
	rest = rest[4:]
	if nkeys != 1 {
		return nil, false, fmt.Errorf("unsupported nkeys=%d", nkeys)
	}

	pubWire, rest, err := readString(rest)
	if err != nil {
		return nil, false, err
	}
	privBlock, rest, err := readString(rest)
	if err != nil {
		return nil, false, err
	}
	if len(rest) != 0 {
		return nil, false, errors.New("trailing data nach private key")
	}

	fixedPriv, privChanged, err := fixPrivateBlockPadding(privBlock)
	if err != nil {
		return nil, false, err
	}
	if !privChanged {
		out := make([]byte, len(pem))
		copy(out, pem)
		return out, false, nil
	}

	var buf bytes.Buffer
	buf.WriteString(magic)
	writeString(&buf, cipherName)
	writeString(&buf, kdfName)
	writeString(&buf, kdfOpts)
	_ = binary.Write(&buf, binary.BigEndian, uint32(1))
	writeString(&buf, pubWire)
	writeString(&buf, fixedPriv)

	return wrapPEM(buf.Bytes()), true, nil
}

func fixPrivateBlockPadding(priv []byte) ([]byte, bool, error) {
	if len(priv) < 8 {
		return nil, false, errors.New("private block zu kurz")
	}
	check1 := binary.BigEndian.Uint32(priv[0:4])
	check2 := binary.BigEndian.Uint32(priv[4:8])
	if check1 != check2 {
		return nil, false, errors.New("checkint mismatch")
	}
	rest := priv[8:]
	keyType, rest, err := readString(rest)
	if err != nil {
		return nil, false, err
	}
	rest, err = skipKeyMaterial(string(keyType), rest)
	if err != nil {
		return nil, false, err
	}
	_, rest, err = readString(rest) // comment
	if err != nil {
		return nil, false, err
	}

	contentLen := len(priv) - len(rest) // bytes through end of comment
	pad := rest
	wantLen := (8 - (contentLen % 8)) % 8
	want := make([]byte, wantLen)
	for i := range want {
		want[i] = byte(i + 1)
	}
	if bytes.Equal(pad, want) {
		return priv, false, nil
	}

	out := make([]byte, contentLen+wantLen)
	copy(out, priv[:contentLen])
	copy(out[contentLen:], want)
	return out, true, nil
}

func skipKeyMaterial(keyType string, rest []byte) ([]byte, error) {
	var err error
	switch keyType {
	case "ssh-ed25519":
		if rest, err = skipString(rest); err != nil {
			return nil, err
		}
		if rest, err = skipString(rest); err != nil {
			return nil, err
		}
		return rest, nil
	case "ssh-rsa":
		for i := 0; i < 6; i++ { // n e d iqmp p q
			if rest, err = skipString(rest); err != nil {
				return nil, err
			}
		}
		return rest, nil
	case "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521":
		if rest, err = skipString(rest); err != nil {
			return nil, err
		}
		if rest, err = skipString(rest); err != nil {
			return nil, err
		}
		if rest, err = skipString(rest); err != nil {
			return nil, err
		}
		return rest, nil
	case "ssh-dss":
		for i := 0; i < 5; i++ {
			if rest, err = skipString(rest); err != nil {
				return nil, err
			}
		}
		return rest, nil
	default:
		return nil, fmt.Errorf("unbekannter key-typ %q", keyType)
	}
}

func extractPEMBody(pem []byte) (string, bool) {
	s := string(pem)
	start := strings.Index(s, pemBegin)
	end := strings.Index(s, pemEnd)
	if start < 0 || end < 0 || end <= start {
		return "", false
	}
	body := s[start+len(pemBegin) : end]
	body = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, body)
	return body, true
}

func wrapPEM(raw []byte) []byte {
	b64 := base64.StdEncoding.EncodeToString(raw)
	var b strings.Builder
	b.WriteString(pemBegin)
	b.WriteByte('\n')
	for i := 0; i < len(b64); i += 70 {
		j := i + 70
		if j > len(b64) {
			j = len(b64)
		}
		b.WriteString(b64[i:j])
		b.WriteByte('\n')
	}
	b.WriteString(pemEnd)
	b.WriteByte('\n')
	return []byte(b.String())
}

func readString(in []byte) (val, rest []byte, err error) {
	if len(in) < 4 {
		return nil, nil, errors.New("string length fehlt")
	}
	n := binary.BigEndian.Uint32(in[:4])
	in = in[4:]
	if uint32(len(in)) < n {
		return nil, nil, errors.New("string truncated")
	}
	return in[:n], in[n:], nil
}

func skipString(in []byte) ([]byte, error) {
	_, rest, err := readString(in)
	return rest, err
}

func writeString(buf *bytes.Buffer, val []byte) {
	_ = binary.Write(buf, binary.BigEndian, uint32(len(val)))
	buf.Write(val)
}
