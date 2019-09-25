// Copyright 2019 The Gogs Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package models

import (
	"fmt"

	"github.com/duo-labs/webauthn/webauthn"
	"github.com/duo-labs/webauthn/protocol"
)

// WebAuthentication represents a web authentication token
type WebAuthentication struct {
	ID       int64
	UserID   int64
	CredID   []byte
	PubKey   []byte
}

func NewWebAuthentication(userID int64, cred webauthn.Credential) error {
	sess := x.NewSession()
	defer sess.Close()
	if err := sess.Begin(); err != nil {
		return err
	}

	if _, err := sess.Insert(&WebAuthentication { UserID: userID, CredID: cred.ID, PubKey: cred.PublicKey }); err != nil {
		return fmt.Errorf("insert webauthentication: %v", err)
	}

	return sess.Commit()
}

func GetCredentials(userID int64) []webauthn.Credential {
	auths := make([]WebAuthentication, 0, 5)
	x.Where("user_id = ?", userID).Find(&auths)
	creds := make([]webauthn.Credential, len(auths))
	for i := range(auths) {
		creds[i].ID = auths[i].CredID
		creds[i].PublicKey = auths[i].PubKey
		creds[i].AttestationType = "none"
	}

	return creds
}

func GetCredentialDescriptors(userID int64) []protocol.CredentialDescriptor {
	creds := GetCredentials(userID)
	descs := make([]protocol.CredentialDescriptor, len(creds))
	for i := range(creds) {
		descs[i].Type = "public-key"
		descs[i].CredentialID = creds[i].ID
	}

	return descs
}
