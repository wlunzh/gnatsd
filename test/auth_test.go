// Copyright 2012-2018 The NATS Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/nats-io/jwt"
	"github.com/nats-io/nkeys"

	"github.com/nats-io/gnatsd/server"
)

func doAuthConnect(t tLogger, c net.Conn, token, user, pass string) {
	cs := fmt.Sprintf("CONNECT {\"verbose\":true,\"auth_token\":\"%s\",\"user\":\"%s\",\"pass\":\"%s\"}\r\n", token, user, pass)
	sendProto(t, c, cs)
}

func testInfoForAuth(t tLogger, infojs []byte) bool {
	var sinfo server.Info
	err := json.Unmarshal(infojs, &sinfo)
	if err != nil {
		t.Fatalf("Could not unmarshal INFO json: %v\n", err)
	}
	return sinfo.AuthRequired
}

func expectAuthRequired(t tLogger, c net.Conn) {
	buf := expectResult(t, c, infoRe)
	infojs := infoRe.FindAllSubmatch(buf, 1)[0][1]
	if !testInfoForAuth(t, infojs) {
		t.Fatalf("Expected server to require authorization: '%s'", infojs)
	}
}

////////////////////////////////////////////////////////////
// The authorization token version
////////////////////////////////////////////////////////////

const AUTH_PORT = 10422
const AUTH_TOKEN = "_YZZ22_"

func runAuthServerWithToken() *server.Server {
	opts := DefaultTestOptions
	opts.Port = AUTH_PORT
	opts.Authorization = AUTH_TOKEN
	return RunServer(&opts)
}

func TestNoAuthClient(t *testing.T) {
	s := runAuthServerWithToken()
	defer s.Shutdown()
	c := createClientConn(t, "127.0.0.1", AUTH_PORT)
	defer c.Close()
	expectAuthRequired(t, c)
	doAuthConnect(t, c, "", "", "")
	expectResult(t, c, errRe)
}

func TestAuthClientBadToken(t *testing.T) {
	s := runAuthServerWithToken()
	defer s.Shutdown()
	c := createClientConn(t, "127.0.0.1", AUTH_PORT)
	defer c.Close()
	expectAuthRequired(t, c)
	doAuthConnect(t, c, "ZZZ", "", "")
	expectResult(t, c, errRe)
}

func TestAuthClientNoConnect(t *testing.T) {
	s := runAuthServerWithToken()
	defer s.Shutdown()
	c := createClientConn(t, "127.0.0.1", AUTH_PORT)
	defer c.Close()
	expectAuthRequired(t, c)
	// This is timing dependent..
	time.Sleep(server.AUTH_TIMEOUT)
	expectResult(t, c, errRe)
}

func TestAuthClientGoodConnect(t *testing.T) {
	s := runAuthServerWithToken()
	defer s.Shutdown()
	c := createClientConn(t, "127.0.0.1", AUTH_PORT)
	defer c.Close()
	expectAuthRequired(t, c)
	doAuthConnect(t, c, AUTH_TOKEN, "", "")
	expectResult(t, c, okRe)
}

func TestAuthClientFailOnEverythingElse(t *testing.T) {
	s := runAuthServerWithToken()
	defer s.Shutdown()
	c := createClientConn(t, "127.0.0.1", AUTH_PORT)
	defer c.Close()
	expectAuthRequired(t, c)
	sendProto(t, c, "PUB foo 2\r\nok\r\n")
	expectResult(t, c, errRe)
}

////////////////////////////////////////////////////////////
// The username/password version
////////////////////////////////////////////////////////////

const AUTH_USER = "derek"
const AUTH_PASS = "foobar"

func runAuthServerWithUserPass() *server.Server {
	opts := DefaultTestOptions
	opts.Port = AUTH_PORT
	opts.Username = AUTH_USER
	opts.Password = AUTH_PASS
	return RunServer(&opts)
}

func TestNoUserOrPasswordClient(t *testing.T) {
	s := runAuthServerWithUserPass()
	defer s.Shutdown()
	c := createClientConn(t, "127.0.0.1", AUTH_PORT)
	defer c.Close()
	expectAuthRequired(t, c)
	doAuthConnect(t, c, "", "", "")
	expectResult(t, c, errRe)
}

func TestBadUserClient(t *testing.T) {
	s := runAuthServerWithUserPass()
	defer s.Shutdown()
	c := createClientConn(t, "127.0.0.1", AUTH_PORT)
	defer c.Close()
	expectAuthRequired(t, c)
	doAuthConnect(t, c, "", "derekzz", AUTH_PASS)
	expectResult(t, c, errRe)
}

func TestBadPasswordClient(t *testing.T) {
	s := runAuthServerWithUserPass()
	defer s.Shutdown()
	c := createClientConn(t, "127.0.0.1", AUTH_PORT)
	defer c.Close()
	expectAuthRequired(t, c)
	doAuthConnect(t, c, "", AUTH_USER, "ZZ")
	expectResult(t, c, errRe)
}

func TestPasswordClientGoodConnect(t *testing.T) {
	s := runAuthServerWithUserPass()
	defer s.Shutdown()
	c := createClientConn(t, "127.0.0.1", AUTH_PORT)
	defer c.Close()
	expectAuthRequired(t, c)
	doAuthConnect(t, c, "", AUTH_USER, AUTH_PASS)
	expectResult(t, c, okRe)
}

////////////////////////////////////////////////////////////
// The bcrypt username/password version
////////////////////////////////////////////////////////////

// Generated with util/mkpasswd (Cost 4 because of cost of --race, default is 11)
const BCRYPT_AUTH_PASS = "IW@$6v(y1(t@fhPDvf!5^%"
const BCRYPT_AUTH_HASH = "$2a$04$Q.CgCP2Sl9pkcTXEZHazaeMwPaAkSHk7AI51HkyMt5iJQQyUA4qxq"

func runAuthServerWithBcryptUserPass() *server.Server {
	opts := DefaultTestOptions
	opts.Port = AUTH_PORT
	opts.Username = AUTH_USER
	opts.Password = BCRYPT_AUTH_HASH
	return RunServer(&opts)
}

func TestBadBcryptPassword(t *testing.T) {
	s := runAuthServerWithBcryptUserPass()
	defer s.Shutdown()
	c := createClientConn(t, "127.0.0.1", AUTH_PORT)
	defer c.Close()
	expectAuthRequired(t, c)
	doAuthConnect(t, c, "", AUTH_USER, BCRYPT_AUTH_HASH)
	expectResult(t, c, errRe)
}

func TestGoodBcryptPassword(t *testing.T) {
	s := runAuthServerWithBcryptUserPass()
	defer s.Shutdown()
	c := createClientConn(t, "127.0.0.1", AUTH_PORT)
	defer c.Close()
	expectAuthRequired(t, c)
	doAuthConnect(t, c, "", AUTH_USER, BCRYPT_AUTH_PASS)
	expectResult(t, c, okRe)
}

////////////////////////////////////////////////////////////
// The bcrypt authorization token version
////////////////////////////////////////////////////////////

const BCRYPT_AUTH_TOKEN = "0uhJOSr3GW7xvHvtd^K6pa"
const BCRYPT_AUTH_TOKEN_HASH = "$2a$04$u5ZClXpcjHgpfc61Ee0VKuwI1K3vTC4zq7SjphjnlHMeb1Llkb5Y6"

func runAuthServerWithBcryptToken() *server.Server {
	opts := DefaultTestOptions
	opts.Port = AUTH_PORT
	opts.Authorization = BCRYPT_AUTH_TOKEN_HASH
	return RunServer(&opts)
}

func TestBadBcryptToken(t *testing.T) {
	s := runAuthServerWithBcryptToken()
	defer s.Shutdown()
	c := createClientConn(t, "127.0.0.1", AUTH_PORT)
	defer c.Close()
	expectAuthRequired(t, c)
	doAuthConnect(t, c, BCRYPT_AUTH_TOKEN_HASH, "", "")
	expectResult(t, c, errRe)
}

func TestGoodBcryptToken(t *testing.T) {
	s := runAuthServerWithBcryptToken()
	defer s.Shutdown()
	c := createClientConn(t, "127.0.0.1", AUTH_PORT)
	defer c.Close()
	expectAuthRequired(t, c)
	doAuthConnect(t, c, BCRYPT_AUTH_TOKEN, "", "")
	expectResult(t, c, okRe)
}

////////////////////////////////////////////////////////////
// Accounts, Nonce and JWT
////////////////////////////////////////////////////////////

func runAuthServerWithAccount(acctKey string) *server.Server {
	opts := DefaultTestOptions
	opts.Port = AUTH_PORT
	opts.Account = acctKey
	return RunServer(&opts)
}

func runAuthServerWithAccounts(accts []*jwt.Claims) *server.Server {
	opts := DefaultTestOptions
	opts.Port = AUTH_PORT
	opts.Accounts = accts
	return RunServer(&opts)
}

func doJWTConnect(t tLogger, c net.Conn, sig, acl string) {
	cs := fmt.Sprintf("CONNECT {\"verbose\":true,\"sig\":\"%s\",\"acl\":\"%s\"}\r\n", sig, acl)
	sendProto(t, c, cs)
}

func expectAuthRequiredReturnNonce(t tLogger, c net.Conn) string {
	buf := expectResult(t, c, infoRe)
	infojs := infoRe.FindAllSubmatch(buf, 1)[0][1]
	var sinfo server.Info
	err := json.Unmarshal(infojs, &sinfo)
	if err != nil {
		t.Fatalf("Could not unmarshal INFO json: %v\n", err)
	}

	if !sinfo.AuthRequired {
		t.Fatalf("Expected server to require authorization: '%s'", infojs)
	}

	return sinfo.Nonce
}

func TestGoodAccountLogin(t *testing.T) {
	acct, _ := nkeys.CreateAccount(nil)
	pub, _ := acct.PublicKey()
	user, _ := nkeys.CreateUser(nil)

	claims := jwt.NewClaims()
	claims.Nats["id"], _ = user.PublicKey()

	acl, _ := claims.Encode(acct)

	acctJwt := jwt.NewClaims()
	acctJwt.Issuer = pub
	encoded, _ := acctJwt.Encode(acct)

	s := runAuthServerWithAccount(encoded)
	defer s.Shutdown()

	c := createClientConn(t, "127.0.0.1", AUTH_PORT)
	defer c.Close()

	nonce := []byte(expectAuthRequiredReturnNonce(t, c))
	sig, _ := user.Sign(nonce)
	doJWTConnect(t, c, base64.RawStdEncoding.EncodeToString(sig), acl)
	expectResult(t, c, okRe)
}

func TestGoodAccountLoginUserIsAccount(t *testing.T) {
	acct, _ := nkeys.CreateAccount(nil)
	pub, _ := acct.PublicKey()

	claims := jwt.NewClaims()
	claims.Nats["id"] = pub

	acl, _ := claims.Encode(acct)

	acctJwt := jwt.NewClaims()
	acctJwt.Issuer = pub
	encoded, _ := acctJwt.Encode(acct)

	s := runAuthServerWithAccount(encoded)
	defer s.Shutdown()

	c := createClientConn(t, "127.0.0.1", AUTH_PORT)
	defer c.Close()

	nonce := []byte(expectAuthRequiredReturnNonce(t, c))
	sig, _ := acct.Sign(nonce)
	doJWTConnect(t, c, base64.RawStdEncoding.EncodeToString(sig), acl)
	expectResult(t, c, okRe)
}

func TestGoodAccountLoginFromList(t *testing.T) {
	acct1, _ := nkeys.CreateAccount(nil)
	acct2, _ := nkeys.CreateAccount(nil)
	pub1, _ := acct1.PublicKey()
	pub2, _ := acct2.PublicKey()
	user, _ := nkeys.CreateUser(nil)

	claims := jwt.NewClaims()
	claims.Nats["id"], _ = user.PublicKey()

	acl1, _ := claims.Encode(acct1)
	acl2, _ := claims.Encode(acct2)

	acctJwt1 := jwt.NewClaims()
	acctJwt1.Issuer = pub1
	acctJwt2 := jwt.NewClaims()
	acctJwt2.Issuer = pub2

	s := runAuthServerWithAccounts([]*jwt.Claims{acctJwt1, acctJwt2})
	defer s.Shutdown()

	c1 := createClientConn(t, "127.0.0.1", AUTH_PORT)
	defer c1.Close()
	nonce := []byte(expectAuthRequiredReturnNonce(t, c1))
	sig, _ := user.Sign(nonce)
	doJWTConnect(t, c1, base64.RawStdEncoding.EncodeToString(sig), acl1)
	expectResult(t, c1, okRe)

	c2 := createClientConn(t, "127.0.0.1", AUTH_PORT)
	defer c2.Close()
	nonce = []byte(expectAuthRequiredReturnNonce(t, c2))
	sig, _ = user.Sign(nonce)
	doJWTConnect(t, c2, base64.RawStdEncoding.EncodeToString(sig), acl2)
	expectResult(t, c2, okRe)
}

func TestBadAccountLoginUnknownAcct(t *testing.T) {
	acct1, _ := nkeys.CreateAccount(nil)
	acct2, _ := nkeys.CreateAccount(nil)
	pub2, _ := acct2.PublicKey()
	user, _ := nkeys.CreateUser(nil)

	claims := jwt.NewClaims()
	claims.Nats["id"], _ = user.PublicKey()

	acl1, _ := claims.Encode(acct1)

	acctJwt2 := jwt.NewClaims()
	acctJwt2.Issuer = pub2

	s := runAuthServerWithAccounts([]*jwt.Claims{acctJwt2})
	defer s.Shutdown()

	c1 := createClientConn(t, "127.0.0.1", AUTH_PORT)
	defer c1.Close()

	nonce := []byte(expectAuthRequiredReturnNonce(t, c1))
	sig, _ := user.Sign(nonce)
	doJWTConnect(t, c1, base64.RawStdEncoding.EncodeToString(sig), acl1)
	expectResult(t, c1, errRe)
}

func TestAccountLoginWrongJWT(t *testing.T) {
	acct, _ := nkeys.CreateAccount(nil)
	pub, _ := acct.PublicKey()
	user, _ := nkeys.CreateUser(nil)

	claims := jwt.NewClaims()
	claims.Nats["id"] = "_not_the_user"

	acl, _ := claims.Encode(acct)

	acctJwt := jwt.NewClaims()
	acctJwt.Issuer = pub
	encoded, _ := acctJwt.Encode(acct)

	s := runAuthServerWithAccount(encoded)
	defer s.Shutdown()

	c := createClientConn(t, "127.0.0.1", AUTH_PORT)
	defer c.Close()

	nonce := []byte(expectAuthRequiredReturnNonce(t, c))
	sig, _ := user.Sign(nonce)
	doJWTConnect(t, c, base64.RawStdEncoding.EncodeToString(sig), acl)
	expectResult(t, c, errRe)
}

func TestAccountLoginBadSig(t *testing.T) {
	acct, _ := nkeys.CreateAccount(nil)
	pub, _ := acct.PublicKey()
	user, _ := nkeys.CreateUser(nil)

	claims := jwt.NewClaims()
	claims.Nats["id"], _ = user.PublicKey()

	acl, _ := claims.Encode(acct)

	acctJwt := jwt.NewClaims()
	acctJwt.Issuer = pub
	encoded, _ := acctJwt.Encode(acct)

	s := runAuthServerWithAccount(encoded)
	defer s.Shutdown()

	c := createClientConn(t, "127.0.0.1", AUTH_PORT)
	defer c.Close()

	nonce := []byte(expectAuthRequiredReturnNonce(t, c))
	sig, _ := user.Sign(nonce)

	if sig[0] == 1 {
		sig[0] = 2
	} else {
		sig[0] = 1
	}

	doJWTConnect(t, c, base64.RawStdEncoding.EncodeToString(sig), acl)
	expectResult(t, c, errRe)
}

func TestAccountLoginBadID(t *testing.T) {
	acct, _ := nkeys.CreateAccount(nil)
	pub, _ := acct.PublicKey()
	user, _ := nkeys.CreateUser(nil)

	claims := jwt.NewClaims()
	claims.Nats["id"], _ = user.PublicKey()

	acl, _ := claims.Encode(acct)

	acctJwt := jwt.NewClaims()
	acctJwt.Issuer = pub
	encoded, _ := acctJwt.Encode(acct)

	s := runAuthServerWithAccount(encoded)
	defer s.Shutdown()

	c := createClientConn(t, "127.0.0.1", AUTH_PORT)
	defer c.Close()

	nonce := []byte(expectAuthRequiredReturnNonce(t, c))
	sig, _ := user.Sign(nonce)

	// Send the id of the acct as the id - this is wrong
	cs := fmt.Sprintf("CONNECT {\"verbose\":true,\"sig\":\"%s\",\"acl\":\"%s\",\"id\":\"%s\"}\r\n", base64.RawStdEncoding.EncodeToString(sig), acl, pub)
	sendProto(t, c, cs)
	expectResult(t, c, errRe)
}

func TestAccountLoginMatchingID(t *testing.T) {
	acct, _ := nkeys.CreateAccount(nil)
	pub, _ := acct.PublicKey()
	user, _ := nkeys.CreateUser(nil)
	userPub, _ := user.PublicKey()

	claims := jwt.NewClaims()
	claims.Nats["id"], _ = user.PublicKey()

	acl, _ := claims.Encode(acct)

	acctJwt := jwt.NewClaims()
	acctJwt.Issuer = pub
	encoded, _ := acctJwt.Encode(acct)

	s := runAuthServerWithAccount(encoded)
	defer s.Shutdown()

	c := createClientConn(t, "127.0.0.1", AUTH_PORT)
	defer c.Close()

	nonce := []byte(expectAuthRequiredReturnNonce(t, c))
	sig, _ := user.Sign(nonce)

	// Send the id of the user as the id - this is ok
	cs := fmt.Sprintf("CONNECT {\"verbose\":true,\"sig\":\"%s\",\"acl\":\"%s\",\"id\":\"%s\"}\r\n", base64.RawStdEncoding.EncodeToString(sig), acl, userPub)
	sendProto(t, c, cs)
	expectResult(t, c, errRe)
}

////////////////////////////////////////////////////////////
// ClientKey and Nonce
////////////////////////////////////////////////////////////

func runAuthServerWithClientKey(clientKey string) *server.Server {
	opts := DefaultTestOptions
	opts.Port = AUTH_PORT
	opts.ClientKey = clientKey
	opts.AuthTimeout = 120
	return RunServer(&opts)
}

func runAuthServerWithClientKeys(keys []string) *server.Server {
	opts := DefaultTestOptions
	opts.Port = AUTH_PORT
	opts.ClientKeys = keys
	return RunServer(&opts)
}

func doClientKeyConnect(t tLogger, c net.Conn, sig, id string) {
	cs := fmt.Sprintf("CONNECT {\"verbose\":true,\"sig\":\"%s\",\"id\":\"%s\"}\r\n", sig, id)
	sendProto(t, c, cs)
}

func TestGoodClientKeyLogin(t *testing.T) {
	user, _ := nkeys.CreateUser(nil)
	pub, _ := user.PublicKey()

	s := runAuthServerWithClientKey(pub)
	defer s.Shutdown()

	c := createClientConn(t, "127.0.0.1", AUTH_PORT)
	defer c.Close()

	nonce := []byte(expectAuthRequiredReturnNonce(t, c))
	sig, _ := user.Sign(nonce)
	doClientKeyConnect(t, c, base64.RawStdEncoding.EncodeToString(sig), pub)
	expectResult(t, c, okRe)
}

func TestGoodClientKeyLoginFromList(t *testing.T) {
	user1, _ := nkeys.CreateUser(nil)
	user2, _ := nkeys.CreateUser(nil)
	pub1, _ := user1.PublicKey()
	pub2, _ := user2.PublicKey()

	s := runAuthServerWithClientKeys([]string{pub1, pub2})
	defer s.Shutdown()

	c1 := createClientConn(t, "127.0.0.1", AUTH_PORT)
	defer c1.Close()
	nonce := []byte(expectAuthRequiredReturnNonce(t, c1))
	sig, _ := user1.Sign(nonce)
	doClientKeyConnect(t, c1, base64.RawStdEncoding.EncodeToString(sig), pub1)
	expectResult(t, c1, okRe)

	c2 := createClientConn(t, "127.0.0.1", AUTH_PORT)
	defer c2.Close()
	nonce = []byte(expectAuthRequiredReturnNonce(t, c2))
	sig, _ = user2.Sign(nonce)
	doClientKeyConnect(t, c2, base64.RawStdEncoding.EncodeToString(sig), pub2)
	expectResult(t, c2, okRe)
}

func TestBadClientKeyLogin(t *testing.T) {
	user, _ := nkeys.CreateUser(nil)
	pub, _ := user.PublicKey()
	user2, _ := nkeys.CreateUser(nil)
	pub2, _ := user2.PublicKey()

	s := runAuthServerWithClientKey(pub2)
	defer s.Shutdown()

	c := createClientConn(t, "127.0.0.1", AUTH_PORT)
	defer c.Close()

	nonce := []byte(expectAuthRequiredReturnNonce(t, c))
	sig, _ := user.Sign(nonce)
	doClientKeyConnect(t, c, base64.RawStdEncoding.EncodeToString(sig), pub)
	expectResult(t, c, errRe)
}

func TestClientKeyLoginBadSig(t *testing.T) {
	user, _ := nkeys.CreateUser(nil)
	pub, _ := user.PublicKey()

	s := runAuthServerWithClientKey(pub)
	defer s.Shutdown()

	c := createClientConn(t, "127.0.0.1", AUTH_PORT)
	defer c.Close()

	nonce := []byte(expectAuthRequiredReturnNonce(t, c))
	sig, _ := user.Sign(nonce)
	if sig[0] == 1 {
		sig[0] = 2
	} else {
		sig[0] = 1
	}
	doClientKeyConnect(t, c, base64.RawStdEncoding.EncodeToString(sig), pub)
	expectResult(t, c, errRe)
}

func TestBadClientKeyLoginFromList(t *testing.T) {
	user1, _ := nkeys.CreateUser(nil)
	user2, _ := nkeys.CreateUser(nil)
	user3, _ := nkeys.CreateUser(nil)
	pub1, _ := user1.PublicKey()
	pub2, _ := user2.PublicKey()
	pub3, _ := user3.PublicKey()

	s := runAuthServerWithClientKeys([]string{pub1, pub2})
	defer s.Shutdown()

	c1 := createClientConn(t, "127.0.0.1", AUTH_PORT)
	defer c1.Close()
	nonce := []byte(expectAuthRequiredReturnNonce(t, c1))
	sig, _ := user3.Sign(nonce)
	doClientKeyConnect(t, c1, base64.RawStdEncoding.EncodeToString(sig), pub3)
	expectResult(t, c1, errRe)
}
