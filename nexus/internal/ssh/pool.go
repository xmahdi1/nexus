package ssh

import (
	"context"
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
	ctx         context.Context
	cancel      context.CancelFunc
	reaped      chan struct{}
	mu          sync.Mutex
	entries     map[string]*poolEntry
	hostKeyFunc HostKeyCallback
}

func NewPool() *Pool {
	ctx, cancel := context.WithCancel(context.Background())
	p := &Pool{ctx: ctx, cancel: cancel, reaped: make(chan struct{}), entries: make(map[string]*poolEntry)}
	go p.reap()
	return p
}

func (p *Pool) Close() {
	p.cancel()
	p.mu.Lock()
	for id, entry := range p.entries {
		entry.client.Close()
		delete(p.entries, id)
	}
	p.mu.Unlock()
	<-p.reaped
}

func (p *Pool) SetHostKeyCallback(fn HostKeyCallback) {
	p.mu.Lock()
	p.hostKeyFunc = fn
	p.mu.Unlock()
}

func (p *Pool) Get(cfg ServerConfig) (*ssh.Client, error) {
	return p.GetContext(context.Background(), cfg)
}
func (p *Pool) GetContext(parent context.Context, cfg ServerConfig) (*ssh.Client, error) {
	if p.ctx.Err() != nil {
		return nil, net.ErrClosed
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	stop := context.AfterFunc(p.ctx, cancel)
	defer stop()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	p.mu.Lock()
	entry, exists := p.entries[cfg.ID]
	hkFunc := p.hostKeyFunc
	p.mu.Unlock()

	if exists {
		result := make(chan error, 1)
		go func() { _, _, err := entry.client.SendRequest("keepalive@openssh.com", true, nil); result <- err }()
		select {
		case err := <-result:
			if err == nil && ctx.Err() == nil {
				p.mu.Lock()
				if p.entries[cfg.ID] == entry && p.ctx.Err() == nil {
					entry.lastUsed = time.Now()
					p.mu.Unlock()
					return entry.client, nil
				}
				p.mu.Unlock()
			}
			p.remove(cfg.ID, entry)
		case <-ctx.Done():
			p.remove(cfg.ID, entry)
			return nil, ctx.Err()
		}
	}

	client, err := p.dial(ctx, cfg, hkFunc)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	if p.ctx.Err() != nil {
		p.mu.Unlock()
		client.Close()
		return nil, net.ErrClosed
	}
	if current, ok := p.entries[cfg.ID]; ok {
		p.mu.Unlock()
		client.Close()
		return current.client, nil
	}
	p.entries[cfg.ID] = &poolEntry{client: client, lastUsed: time.Now()}
	p.mu.Unlock()
	return client, nil
}

func (p *Pool) Remove(id string) { p.remove(id, nil) }

func (p *Pool) remove(id string, expected *poolEntry) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if e := p.entries[id]; e != nil && (expected == nil || e == expected) {
		e.client.Close()
		delete(p.entries, id)
	}
}

func (p *Pool) reap() {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()
	defer close(p.reaped)
	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
		}
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

func (p *Pool) dial(ctx context.Context, cfg ServerConfig, hkFunc HostKeyCallback) (*ssh.Client, error) {
	signer, err := ssh.ParsePrivateKey(cfg.PrivKey)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	var hkc ssh.HostKeyCallback
	if hkFunc == nil {
		return nil, fmt.Errorf("host key verification is required")
	} else {
		id := cfg.ID
		hkc = func(_ string, _ net.Addr, key ssh.PublicKey) error {
			return hkFunc(id, ssh.FingerprintSHA256(key))
		}
	}
	address := net.JoinHostPort(cfg.Host, fmt.Sprint(cfg.Port))
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		raw.SetDeadline(deadline)
	}
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	defer stop()
	connection, channels, requests, err := ssh.NewClientConn(raw, address, &ssh.ClientConfig{User: cfg.User, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: hkc})
	if err != nil {
		raw.Close()
		return nil, fmt.Errorf("dial %s: %w", cfg.Host, err)
	}
	if err := ctx.Err(); err != nil {
		connection.Close()
		return nil, err
	}
	stop()
	if err := raw.SetDeadline(time.Time{}); err != nil {
		connection.Close()
		return nil, err
	}
	client := ssh.NewClient(connection, channels, requests)
	return client, nil
}
