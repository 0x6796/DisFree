package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	openVPNDataV2Opcode = 9
	openVPNKeyID0       = 0
	openVPNGCMTagSize   = 16
)

func dataV2Header(peerID uint32, keyID uint8) ([4]byte, error) {
	var h [4]byte
	if peerID > 0xFFFFFF {
		return h, fmt.Errorf("peer-id %d exceeds 24 bits", peerID)
	}
	if keyID > 7 {
		return h, fmt.Errorf("key-id %d exceeds 3 bits", keyID)
	}
	v := (uint32((openVPNDataV2Opcode<<3)|int(keyID)) << 24) | (peerID & 0xFFFFFF)
	binary.BigEndian.PutUint32(h[:], v)
	return h, nil
}

func newOpenVPNGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("AES-256-GCM requires 32-byte key, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if gcm.NonceSize() != 12 || gcm.Overhead() != openVPNGCMTagSize {
		return nil, fmt.Errorf("unexpected GCM parameters nonce=%d tag=%d", gcm.NonceSize(), gcm.Overhead())
	}
	return gcm, nil
}

func openVPNGCMNonce(packetID [4]byte, hmacKey []byte) ([12]byte, error) {
	var nonce [12]byte
	if len(hmacKey) < 8 {
		return nonce, errors.New("implicit-IV source shorter than 8 bytes")
	}
	copy(nonce[0:4], packetID[:])
	copy(nonce[4:12], hmacKey[:8])
	return nonce, nil
}

// encryptDataV2 implements the legacy OpenVPN AEAD wire format:
// [opcode+peer-id:4][packet-id:4][GCM-tag:16][ciphertext].
// AAD is opcode+peer-id+packet-id. The 12-byte GCM nonce is packet-id
// followed by the first 8 bytes of the direction's HMAC key material.
func encryptDataV2(peerID uint32, keyID uint8, packetID uint32, aesKey, hmacKey, plaintext []byte) ([]byte, error) {
	if packetID == 0 {
		return nil, errors.New("packet-id 0 is not valid for data channel send")
	}
	header, err := dataV2Header(peerID, keyID)
	if err != nil {
		return nil, err
	}
	var pid [4]byte
	binary.BigEndian.PutUint32(pid[:], packetID)
	nonce, err := openVPNGCMNonce(pid, hmacKey)
	if err != nil {
		return nil, err
	}
	gcm, err := newOpenVPNGCM(aesKey)
	if err != nil {
		return nil, err
	}
	aad := make([]byte, 0, 8)
	aad = append(aad, header[:]...)
	aad = append(aad, pid[:]...)
	sealed := gcm.Seal(nil, nonce[:], plaintext, aad)
	if len(sealed) != len(plaintext)+openVPNGCMTagSize {
		return nil, errors.New("unexpected GCM sealed length")
	}
	tag := sealed[len(plaintext):]
	ciphertext := sealed[:len(plaintext)]

	out := make([]byte, 0, 4+4+16+len(ciphertext))
	out = append(out, header[:]...)
	out = append(out, pid[:]...)
	out = append(out, tag...)
	out = append(out, ciphertext...)
	return out, nil
}

type decryptedDataV2 struct {
	PeerID   uint32
	KeyID    uint8
	PacketID uint32
	Payload  []byte
}

func decryptDataV2(packet, aesKey, hmacKey []byte) (decryptedDataV2, error) {
	var out decryptedDataV2
	if len(packet) < 4+4+openVPNGCMTagSize+1 {
		return out, fmt.Errorf("P_DATA_V2 too short: %d", len(packet))
	}
	opcode := packet[0] >> 3
	if opcode != openVPNDataV2Opcode {
		return out, fmt.Errorf("not P_DATA_V2: opcode=%d", opcode)
	}
	out.KeyID = packet[0] & 0x07
	out.PeerID = uint32(packet[1])<<16 | uint32(packet[2])<<8 | uint32(packet[3])
	out.PacketID = binary.BigEndian.Uint32(packet[4:8])
	if out.PacketID == 0 {
		return out, errors.New("received data packet-id 0")
	}

	var pid [4]byte
	copy(pid[:], packet[4:8])
	nonce, err := openVPNGCMNonce(pid, hmacKey)
	if err != nil {
		return out, err
	}
	gcm, err := newOpenVPNGCM(aesKey)
	if err != nil {
		return out, err
	}

	aad := packet[:8]
	tag := packet[8:24]
	ciphertext := packet[24:]
	sealed := make([]byte, 0, len(ciphertext)+len(tag))
	sealed = append(sealed, ciphertext...)
	sealed = append(sealed, tag...)
	plaintext, err := gcm.Open(nil, nonce[:], sealed, aad)
	if err != nil {
		return out, fmt.Errorf("AES-GCM authentication: %w", err)
	}
	out.Payload = plaintext
	return out, nil
}
