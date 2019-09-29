// Copyright 2017 The Gogs Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package models

import (
	"encoding/base64"
	"fmt"
	"time"

	"github.com/Unknwon/com"
	"github.com/go-xorm/xorm"
	"github.com/pquerna/otp/totp"
	log "gopkg.in/clog.v1"

	"github.com/gogs/gogs/models/errors"
	"github.com/gogs/gogs/pkg/setting"
	"github.com/gogs/gogs/pkg/tool"
)

// TwoFactor represents a two-factor authentication token.
type TwoFactor struct {
	ID          int64
	UserID      int64 `xorm:"UNIQUE"`
	Secret      string
	Created     time.Time `xorm:"-" json:"-"`
	CreatedUnix int64
}

func (t *TwoFactor) BeforeInsert() {
	t.CreatedUnix = time.Now().Unix()
}

func (t *TwoFactor) AfterSet(colName string, _ xorm.Cell) {
	switch colName {
	case "created_unix":
		t.Created = time.Unix(t.CreatedUnix, 0).Local()
	}
}

// ValidateTOTP returns true if given passcode is valid for two-factor authentication token.
// It also returns possible validation error.
func (t *TwoFactor) ValidateTOTP(passcode string) (bool, error) {
	secret, err := base64.StdEncoding.DecodeString(t.Secret)
	if err != nil {
		return false, fmt.Errorf("DecodeString: %v", err)
	}
	decryptSecret, err := com.AESGCMDecrypt(tool.MD5Bytes(setting.SecretKey), secret)
	if err != nil {
		return false, fmt.Errorf("AESGCMDecrypt: %v", err)
	}
	return totp.Validate(passcode, string(decryptSecret)), nil
}

// IsUserEnabledTwoFactor returns true if user has enabled two-factor authentication.
func IsUserEnabledTwoFactor(userID int64) bool {
	has, err := x.Where("user_id = ?", userID).Get(new(TwoFactor))
	if err != nil {
		log.Error(2, "IsUserEnabledTwoFactor [user_id: %d]: %v", userID, err)
	}
	return has
}

// NewTwoFactor creates a new two-factor authentication token and recovery codes for given user.
func NewTwoFactor(userID int64, secret string) error {
	t := &TwoFactor{
		UserID: userID,
	}

	// Encrypt secret
	encryptSecret, err := com.AESGCMEncrypt(tool.MD5Bytes(setting.SecretKey), []byte(secret))
	if err != nil {
		return fmt.Errorf("AESGCMEncrypt: %v", err)
	}
	t.Secret = base64.StdEncoding.EncodeToString(encryptSecret)

	recoveryCodes, err := generateRecoveryCodes(userID)
	if err != nil {
		return fmt.Errorf("generateRecoveryCodes: %v", err)
	}

	sess := x.NewSession()
	defer sess.Close()
	if err = sess.Begin(); err != nil {
		return err
	}

	if _, err = sess.Insert(t); err != nil {
		return fmt.Errorf("insert two-factor: %v", err)
	} else if _, err = sess.Insert(recoveryCodes); err != nil {
		return fmt.Errorf("insert recovery codes: %v", err)
	}

	return sess.Commit()
}

// GetTwoFactorByUserID returns two-factor authentication token of given user.
func GetTwoFactorByUserID(userID int64) (*TwoFactor, error) {
	t := new(TwoFactor)
	has, err := x.Where("user_id = ?", userID).Get(t)
	if err != nil {
		return nil, err
	} else if !has {
		return nil, errors.TwoFactorNotFound{userID}
	}

	return t, nil
}

// DeleteTwoFactor removes two-factor authentication token and recovery codes of given user.
func DeleteTwoFactor(userID int64) (err error) {
	sess := x.NewSession()
	defer sess.Close()
	if err = sess.Begin(); err != nil {
		return err
	}

	if _, err = sess.Where("user_id = ?", userID).Delete(new(TwoFactor)); err != nil {
		return fmt.Errorf("delete two-factor: %v", err)
	} else if err = deleteRecoveryCodesByUserID(sess, userID); err != nil {
		return fmt.Errorf("deleteRecoveryCodesByUserID: %v", err)
	}

	return sess.Commit()
}
