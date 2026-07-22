package ssh

import (
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

const idleTimeout = 10 * time.Minute

type HostKeyCallback func(serverID, fingerprint string) error

type ServerConfig struct {
	ID      string
	Host    string
	Port    int
	User    string
	PrivKey []byte
}

type poolEntry struct {
	client   *ssh.Client
	lastUsed time.Time
}

type Pool struct {
	mu          sync.Mutex
	entries     map[string]*poolEntry
	hostKeyFunc HostKeyCallback
}

func NewPool() *Pool {
	p := &Pool{entries: make(map[string]*poolEntry)}
	go p.reap()
	return p
}

func (p *Pool) SetHostKeyCallback(fn HostKeyCallback) {
	p.mu.Lock()
	p.hostKeyFunc = fn
	p.mu.Unlock()
}

func (p *Pool) Get(cfg ServerConfig) (*ssh.Client, error) {
	p.mu.Lock()
	entry, exists := p.entries[cfg.ID]
	hkFunc := p.hostKeyFunc
	p.mu.Unlock()

	if exists {
		if _, _, err := entry.client.SendRequest("keepalive@openssh.com", true, nil); err == nil {
			p.mu.Lock()
			entry.lastUsed = time.Now()
			p.mu.Unlock()
			return entry.client, nil
		}
		p.remove(cfg.ID)
	}

	client, err := p.dial(cfg, hkFunc)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	p.entries[cfg.ID] = &poolEntry{client: client, lastUsed: time.Now()}
	p.mu.Unlock()
	return client, nil
}

func (p *Pool) Remove(id string) { p.remove(id) }

func (p *Pool) remove(id string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if e, ok := p.entries[id]; ok {
		e.client.Close()
		delete(p.entries, id)
	}
}

func (p *Pool) reap() {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		p.mu.Lock()
		for id, e := range p.entries {
			if time.Since(e.lastUsed) > idleTimeout {
				e.client.Close()
				delete(p.entries, id)
			}
		}
		p.mu.Unlock()
	}
}

func (p *Pool) dial(cfg ServerConfig, hkFunc HostKeyCallback) (*ssh.Client, error) {
	signer, err := ssh.ParsePrivateKey(cfg.PrivKey)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	var hkc ssh.HostKeyCallback
	if hkFunc == nil {
		hkc = ssh.InsecureIgnoreHostKey()
	} else {
		id := cfg.ID
		hkc = func(_ string, _ net.Addr, key ssh.PublicKey) error {
			return hkFunc(id, ssh.FingerprintSHA256(key))
		}
	}
	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", cfg.Host, cfg.Port), &ssh.ClientConfig{
		User:            cfg.User,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: hkc,
		Timeout:         10 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", cfg.Host, err)
	}
	return client, nil
}
