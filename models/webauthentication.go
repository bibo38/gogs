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

func DeleteWebAuthenticationKey(userID int64, keyID int64) error {
	key := new(WebAuthentication)
	if _, err := x.Id(keyID).Get(key); err != nil {
		return err
	}

	// TODO Maybe check Admin
	if key.UserID != userID {
		return fmt.Errorf("Key doesn't belong to that user!")
	}

	sess := x.NewSession()
	defer sess.Close()
	if err := sess.Begin(); err != nil {
		return err
	}

	if _, err := sess.Id(keyID).Delete(new(WebAuthentication)); err != nil {
		return err
	}

	return sess.Commit()
}

func GetWebAuthenticationKeys(userID int64) []WebAuthentication {
	auths := make([]WebAuthentication, 0, 5)
	x.Where("user_id = ?", userID).Find(&auths)
	return auths
}

func GetCredentials(userID int64) []webauthn.Credential {
	auths := GetWebAuthenticationKeys(userID)
	creds := make([]webauthn.Credential, len(auths))
	for i, auth := range(auths) {
		creds[i].ID = auth.CredID
		creds[i].PublicKey = auth.PubKey
		creds[i].AttestationType = "none"
	}

	return creds
}

func IsUserEnabledWebAuthentication(userID int64) bool {
	return len(GetWebAuthenticationKeys(userID)) > 0
}

func GetCredentialDescriptors(userID int64) []protocol.CredentialDescriptor {
	auths := GetWebAuthenticationKeys(userID)
	descs := make([]protocol.CredentialDescriptor, len(auths))
	for i, auth := range(auths) {
		descs[i].Type = "public-key"
		descs[i].CredentialID = auth.CredID
	}

	return descs
}
