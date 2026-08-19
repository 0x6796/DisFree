package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"time"
)

type liveVPN struct {
	Endpoint     Endpoint
	Control      *controlUDPConn
	TLS          *tls.Conn
	Session      pushedSession
	Keys         dataKeyBlock
	ResetLatency time.Duration
}

func (v *liveVPN) Close() {
	if v == nil {
		return
	}
	if v.Control != nil {
		_ = v.Control.Close()
	}
	v.Keys = dataKeyBlock{}
}

func establishLiveVPN(ctx context.Context, identityPath string) (*liveVPN, error) {
	svc, err := newAPI().service(ctx)
	if err != nil {
		return nil, err
	}
	ep, err := bestWireEndpoint(ctx, svc, 1800*time.Millisecond)
	if err != nil {
		return nil, err
	}
	id, err := loadOrFetchIdentity(ctx, identityPath)
	if err != nil {
		return nil, err
	}
	trust, err := loadProviderTrust(ctx)
	if err != nil {
		return nil, err
	}

	cc, resetLatency, err := dialControlUDP(ctx, ep, 8*time.Second)
	if err != nil {
		return nil, fmt.Errorf("control reset: %w", err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = cc.Close()
		}
	}()
	_ = cc.SetDeadline(time.Now().Add(15 * time.Second))

	tc := tls.Client(cc, trust.tlsConfigForGateway(ep, id))
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("TLS: %w", err)
	}
	clientSrc, err := randomClientKeySource()
	if err != nil {
		return nil, err
	}
	km, err := marshalClientKeyMethod(clientSrc, ep)
	if err != nil {
		return nil, err
	}
	if _, err := tc.Write(km); err != nil {
		return nil, err
	}
	serverRec, err := readServerKeyMethod(tc)
	if err != nil {
		return nil, err
	}
	master, keys := deriveOpenVPNKeys(clientSrc, serverRec.Source, cc.localSID, cc.remoteSID)
	if _, err := tc.Write([]byte("PUSH_REQUEST\x00")); err != nil {
		return nil, err
	}
	br := bufio.NewReaderSize(tc, 64<<10)
	pushMsgs, err := readPushReply(br)
	if err != nil {
		return nil, err
	}
	ps, err := parsePushedSession(flattenPushOptions(pushMsgs))
	if err != nil {
		return nil, err
	}
	_ = cc.SetDeadline(time.Time{})

	for i := range clientSrc.PreMaster {
		clientSrc.PreMaster[i] = 0
	}
	for i := range master {
		master[i] = 0
	}
	cleanup = false
	return &liveVPN{Endpoint: ep, Control: cc, TLS: tc, Session: ps, Keys: keys, ResetLatency: resetLatency}, nil
}
