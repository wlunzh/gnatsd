// Copyright 2016-2018 The NATS Authors
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
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/nats-io/jwt"
	"github.com/nats-io/nkeys"

	"github.com/nats-io/go-nats"
)

func TestMultipleUserAuth(t *testing.T) {
	srv, opts := RunServerWithConfig("./configs/multi_user.conf")
	defer srv.Shutdown()

	if opts.Users == nil {
		t.Fatal("Expected a user array that is not nil")
	}
	if len(opts.Users) != 2 {
		t.Fatal("Expected a user array that had 2 users")
	}

	// Test first user
	url := fmt.Sprintf("nats://%s:%s@%s:%d/",
		opts.Users[0].Username,
		opts.Users[0].Password,
		opts.Host, opts.Port)

	nc, err := nats.Connect(url)
	if err != nil {
		t.Fatalf("Expected a successful connect, got %v\n", err)
	}
	defer nc.Close()

	if !nc.AuthRequired() {
		t.Fatal("Expected auth to be required for the server")
	}

	// Test second user
	url = fmt.Sprintf("nats://%s:%s@%s:%d/",
		opts.Users[1].Username,
		opts.Users[1].Password,
		opts.Host, opts.Port)

	nc, err = nats.Connect(url)
	if err != nil {
		t.Fatalf("Expected a successful connect, got %v\n", err)
	}
	defer nc.Close()
}

// Resolves to "test"
const testToken = "$2a$05$3sSWEVA1eMCbV0hWavDjXOx.ClBjI6u1CuUdLqf22cbJjXsnzz8/."

func TestTokenInConfig(t *testing.T) {
	confFileName := "test.conf"
	defer os.Remove(confFileName)
	content := `
	listen: 127.0.0.1:4567
	authorization={
		token: ` + testToken + `
		timeout: 5
	}`
	if err := ioutil.WriteFile(confFileName, []byte(content), 0666); err != nil {
		t.Fatalf("Error writing config file: %v", err)
	}
	s, opts := RunServerWithConfig(confFileName)
	defer s.Shutdown()

	url := fmt.Sprintf("nats://test@%s:%d/", opts.Host, opts.Port)
	nc, err := nats.Connect(url)
	if err != nil {
		t.Fatalf("Expected a successful connect, got %v\n", err)
	}
	defer nc.Close()
	if !nc.AuthRequired() {
		t.Fatal("Expected auth to be required for the server")
	}
}

type testAuthHandler struct {
	key nkeys.KeyPair
	acl string
	id  string
}

func (t *testAuthHandler) Sign(nonce []byte) ([]byte, error) {
	return t.key.Sign(nonce)
}

func (t *testAuthHandler) ACL() (string, error) {
	return t.acl, nil
}

func (t *testAuthHandler) ID() (string, error) {
	return t.id, nil
}

func TestMultipleKeyAuth(t *testing.T) {
	srv, opts := RunServerWithConfig("./configs/multi_key.conf")
	defer srv.Shutdown()

	if opts.ClientKeys == nil {
		t.Fatal("Expected a key array that is not nil")
	}
	if len(opts.ClientKeys) != 2 {
		t.Fatal("Expected a key array that had 2 keys")
	}

	// Test first user
	url := fmt.Sprintf("nats://%s:%d/",
		opts.Host, opts.Port)

	seed := "SUAJP574IOPM7XANWNU4MQR4NXV6IMKHMH4YI4G2BHLHC2THRM4NHHGFJ5XMLJSDKGVNKZTY7BE6TRZZG74X7H3RY6O7LI6K7AL6SKPH2P3K4"
	user, _ := nkeys.FromSeed(seed)
	pub, _ := user.PublicKey()
	handler := &testAuthHandler{
		key: user,
		id:  pub,
	}

	nc, err := nats.Connect(url, nats.Auth(handler))
	if err != nil {
		t.Fatalf("Expected a successful connect, got %v\n", err)
	}
	defer nc.Close()

	if !nc.AuthRequired() {
		t.Fatal("Expected auth to be required for the server")
	}

	// Test second user
	seed = "SUAGKUTMGBNQJRKEVFWUMQUJXVXVDOONOODJ6HOANUQHKZRA4ZONPE3BF4BIYPQ3YMT3KRM64UPMBW7ZIPCUTPJCXQAEYKLE55OA25RXJSNXY"
	user, _ = nkeys.FromSeed(seed)
	pub, _ = user.PublicKey()
	handler = &testAuthHandler{
		key: user,
		id:  pub,
	}

	nc, err = nats.Connect(url, nats.Auth(handler))
	if err != nil {
		t.Fatalf("Expected a successful connect, got %v\n", err)
	}
	defer nc.Close()
}

func TestMultipleAccountAuth(t *testing.T) {
	srv, opts := RunServerWithConfig("./configs/multi_acct.conf")
	defer srv.Shutdown()

	if opts.Accounts == nil {
		t.Fatal("Expected a key array that is not nil")
	}
	if len(opts.Accounts) != 2 {
		t.Fatal("Expected a key array that had 2 keys")
	}

	// Test first user
	url := fmt.Sprintf("nats://%s:%d/",
		opts.Host, opts.Port)

	seed := "SAAGEPPTBJ6VEC4FPZ3HA472273BLJFEKPSRYGSR4NH64EJAQC3NB3EOCO2AN2FVNSBDCB5C35RVT76YJOXYCQR6MRRLVPPFK6I7GDKHWAXIG"
	acct, _ := nkeys.FromSeed(seed)
	user, _ := nkeys.CreateUser(nil)
	claims := jwt.NewClaims()
	claims.Nats["id"], _ = user.PublicKey()
	acl, _ := claims.Encode(acct)

	handler := &testAuthHandler{
		key: user,
		acl: acl,
	}

	nc, err := nats.Connect(url, nats.Auth(handler))
	if err != nil {
		t.Fatalf("Expected a successful connect, got %v\n", err)
	}
	defer nc.Close()

	if !nc.AuthRequired() {
		t.Fatal("Expected auth to be required for the server")
	}

	// Test second user

	seed = "SAAGEPPTBJ6VEC4FPZ3HA472273BLJFEKPSRYGSR4NH64EJAQC3NB3EOCO2AN2FVNSBDCB5C35RVT76YJOXYCQR6MRRLVPPFK6I7GDKHWAXIG"
	acct, _ = nkeys.FromSeed(seed)
	user, _ = nkeys.CreateUser(nil)
	claims = jwt.NewClaims()
	claims.Nats["id"], _ = user.PublicKey()
	acl, _ = claims.Encode(acct)

	handler = &testAuthHandler{
		key: user,
		acl: acl,
	}

	nc, err = nats.Connect(url, nats.Auth(handler))
	if err != nil {
		t.Fatalf("Expected a successful connect, got %v\n", err)
	}
	defer nc.Close()
}
