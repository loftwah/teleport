/*
Copyright 2022 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package sqlserver

import (
	"context"
	"crypto/tls"
	"fmt"

	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/srv/db/common"
	"github.com/gravitational/teleport/lib/srv/db/sqlserver/protocol"

	"github.com/gravitational/trace"
	"github.com/sirupsen/logrus"
)

//
type Proxy struct {
	// TLSConfig is the proxy TLS configuration.
	TLSConfig *tls.Config
	// Middleware is the auth middleware.
	Middleware *auth.Middleware
	// Service is used to connect to a remote database service.
	Service common.Service
	// Log is used for logging.
	Log logrus.FieldLogger
}

// HandleConnection accepts connection from a Postgres client, authenticates
// it and proxies it to an appropriate database service.
func (p *Proxy) HandleConnection(ctx context.Context, proxyCtx *common.ProxyContext, tlsConn *tls.Conn) error {
	fmt.Println("=== [PROXY] === SQL SERVER")
	tlsConn, err := p.handlePrelogin(ctx, tlsConn)
	if err != nil {
		return trace.Wrap(err)
	}
	serviceConn, err := p.Service.Connect(ctx, proxyCtx)
	if err != nil {
		return trace.Wrap(err)
	}
	defer serviceConn.Close()
	err = p.Service.Proxy(ctx, proxyCtx, tlsConn, serviceConn)
	if err != nil {
		return trace.Wrap(err)
	}
	return nil
}

func (p *Proxy) handlePrelogin(ctx context.Context, tlsConn *tls.Conn) (*tls.Conn, error) {
	_, err := protocol.ReadPreloginPacket(tlsConn)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	p.Log.Debugf("Got PRELOGIN packet.")

	err = protocol.WritePreloginResponse(tlsConn)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// SQL Server clients don't support client certificates.
	tlsConf := p.TLSConfig.Clone()
	tlsConf.ClientAuth = tls.NoClientCert
	tlsConf.GetConfigForClient = nil

	tlsConn, err = protocol.DoTLSHandshake(tlsConn, tlsConf)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	p.Log.Debugf("Performed TLS handshake.")

	_, err = protocol.ReadLogin7Packet(tlsConn)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	p.Log.Debugf("Got LOGIN7 packet.")

	err = protocol.WriteLogin7Response(tlsConn)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return tlsConn, nil
}
