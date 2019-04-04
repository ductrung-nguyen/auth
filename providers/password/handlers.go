package password

import (
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/ductrung-nguyen/auth"
	"github.com/ductrung-nguyen/auth/auth_identity"
	"github.com/ductrung-nguyen/auth/claims"
	"github.com/go-sql-driver/mysql"
	"github.com/qor/qor/utils"
	"github.com/qor/session"
)

// DefaultAuthorizeHandler default authorize handler
var DefaultAuthorizeHandler = func(context *auth.Context) (*claims.Claims, error) {
	var (
		//authInfo    auth_identity.Basic
		authInfo    auth_identity.AuthIdentity
		req         = context.Request
		tx          = context.Auth.GetDB(req)
		provider, _ = context.Provider.(*Provider)
	)

	req.ParseForm()
	authInfo.Provider = provider.GetName()
	authInfo.UID = strings.TrimSpace(req.Form.Get("login"))

	if tx.Model(context.Auth.AuthIdentityModel).Where(authInfo).Scan(&authInfo).RecordNotFound() {
		return nil, auth.ErrInvalidAccount
	}

	if provider.Config.Confirmable && authInfo.ConfirmedAt == nil {
		currentUser, _ := context.Auth.UserStorer.Get(authInfo.ToClaims(), context)
		provider.Config.ConfirmMailer(authInfo.UID, context, authInfo.ToClaims(), currentUser)

		return nil, ErrUnconfirmed
	}

	if err := provider.Encryptor.Compare(authInfo.EncryptedPassword, strings.TrimSpace(req.Form.Get("password"))); err == nil {
		return authInfo.ToClaims(), err
	}

	return nil, auth.ErrInvalidPassword
}

// DefaultRegisterHandler default register handler
var DefaultRegisterHandler = func(context *auth.Context) (*claims.Claims, error) {
	var (
		err         error
		currentUser interface{}
		schema      auth.Schema
		//authInfo    auth_identity.Basic
		authInfo    auth_identity.AuthIdentity
		req         = context.Request
		tx          = context.Auth.GetDB(req)
		provider, _ = context.Provider.(*Provider)
	)

	req.ParseForm()
	if req.Form.Get("login") == "" {
		return nil, auth.ErrInvalidAccount
	}

	if req.Form.Get("password") == "" {
		return nil, auth.ErrInvalidPassword
	}

	var loginType string

	if req.Form.Get("type") == "" {
		loginType = "email"
	} else {
		loginType = strings.TrimSpace(req.Form.Get("type"))
	}

	authInfo.Provider = provider.GetName()
	authInfo.UID = strings.TrimSpace(req.Form.Get("login"))

	if !tx.Model(context.Auth.AuthIdentityModel).Where(authInfo).Scan(&authInfo).RecordNotFound() {
		return nil, auth.ErrInvalidAccount
	}

	if authInfo.EncryptedPassword, err = provider.Encryptor.Digest(strings.TrimSpace(req.Form.Get("password"))); err == nil {
		schema.Provider = authInfo.Provider
		schema.UID = authInfo.UID
		if loginType == "email" {
			schema.Email = authInfo.UID

		} else if loginType == "phone" {
			schema.Phone = authInfo.UID
		}
		if schema.Phone == "" {
			schema.Phone = fmt.Sprintf("?phone%d", time.Now().UTC().UnixNano())
		}

		if schema.Email == "" {
			schema.Email = fmt.Sprintf("?email%d@singloop.com", time.Now().UTC().UnixNano())
		}

		schema.Username = schema.UID
		schema.RawInfo = req

		currentUser, authInfo.UserID, err = context.Auth.UserStorer.Save(&schema, context)
		if err != nil {
			if sqlError, ok := err.(*mysql.MySQLError); ok && sqlError.Number == 1062 {
				// duplicate entry in some columns
				return nil, auth.ErrAccountExisted
			}
			return nil, err
		}

		// create auth identity
		authIdentity := reflect.New(utils.ModelType(context.Auth.Config.AuthIdentityModel)).Interface()
		if err = tx.Where(authInfo).FirstOrCreate(authIdentity).Error; err == nil {
			if provider.Config.Confirmable {
				context.SessionStorer.Flash(context.Writer, req, session.Message{Message: ConfirmFlashMessage, Type: "success"})
				err = provider.Config.ConfirmMailer(schema.Email, context, authInfo.ToClaims(), currentUser)
			}

			return authInfo.ToClaims(), err
		}
	}

	return nil, err
}
