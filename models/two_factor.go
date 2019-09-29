// Copyright 2017 The Gogs Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package models

import (
	"fmt"
	"strings"


	"github.com/gogs/gogs/models/errors"
	"github.com/gogs/gogs/pkg/tool"
)

func generateRecoveryCodes(userID int64) ([]*TwoFactorRecoveryCode, error) {
	recoveryCodes := make([]*TwoFactorRecoveryCode, 10)
	for i := 0; i < 10; i++ {
		code, err := tool.RandomString(10)
		if err != nil {
			return nil, fmt.Errorf("RandomString: %v", err)
		}
		recoveryCodes[i] = &TwoFactorRecoveryCode{
			UserID: userID,
			Code:   strings.ToLower(code[:5] + "-" + code[5:]),
		}
	}
	return recoveryCodes, nil
}

// TwoFactorRecoveryCode represents a two-factor authentication recovery code.
type TwoFactorRecoveryCode struct {
	ID     int64
	UserID int64
	Code   string `xorm:"VARCHAR(11)"`
	IsUsed bool
}

// GetRecoveryCodesByUserID returns all recovery codes of given user.
func GetRecoveryCodesByUserID(userID int64) ([]*TwoFactorRecoveryCode, error) {
	recoveryCodes := make([]*TwoFactorRecoveryCode, 0, 10)
	return recoveryCodes, x.Where("user_id = ?", userID).Find(&recoveryCodes)
}

// TODO Rename and change it, so that TOTP and WebAuthentication can both call
// this function and it will only delete the codes, if both are disabled
func deleteRecoveryCodesByUserID(e Engine, userID int64) error {
	_, err := e.Where("user_id = ?", userID).Delete(new(TwoFactorRecoveryCode))
	return err
}

// RegenerateRecoveryCodes regenerates new set of recovery codes for given user.
func RegenerateRecoveryCodes(userID int64) error {
	recoveryCodes, err := generateRecoveryCodes(userID)
	if err != nil {
		return fmt.Errorf("generateRecoveryCodes: %v", err)
	}

	sess := x.NewSession()
	defer sess.Close()
	if err = sess.Begin(); err != nil {
		return err
	}

	if err = deleteRecoveryCodesByUserID(sess, userID); err != nil {
		return fmt.Errorf("deleteRecoveryCodesByUserID: %v", err)
	} else if _, err = sess.Insert(recoveryCodes); err != nil {
		return fmt.Errorf("insert new recovery codes: %v", err)
	}

	return sess.Commit()
}

// UseRecoveryCode validates recovery code of given user and marks it is used if valid.
func UseRecoveryCode(userID int64, code string) error {
	recoveryCode := new(TwoFactorRecoveryCode)
	has, err := x.Where("code = ?", code).And("is_used = ?", false).Get(recoveryCode)
	if err != nil {
		return fmt.Errorf("get unused code: %v", err)
	} else if !has {
		return errors.TwoFactorRecoveryCodeNotFound{code}
	}

	recoveryCode.IsUsed = true
	if _, err = x.Id(recoveryCode.ID).Cols("is_used").Update(recoveryCode); err != nil {
		return fmt.Errorf("mark code as used: %v", err)
	}

	return nil
}
