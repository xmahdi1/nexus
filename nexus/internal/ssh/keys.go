package ssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"

	"golang.org/x/crypto/ssh"
)

type KeyPair struct {
	PublicKey   string
	PrivateKey  string 
	Fingerprint string 
}

func GenerateKeyPair() (*KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	privBlock, err := ssh.MarshalPrivateKey(priv, "nexus")
	if err != nil {
		return nil, err
	}
	privPEM := pem.EncodeToMemory(privBlock)

	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, err
	}

	return &KeyPair{
		PublicKey:   string(ssh.MarshalAuthorizedKey(sshPub)),
		PrivateKey:  string(privPEM),
		Fingerprint: ssh.FingerprintSHA256(sshPub),
	}, nil
}