package auth

import (
	"net/http"

	"github.com/jinzhu/gorm"
	"github.com/qor/auth/claims"
	"github.com/qor/qor/utils"
)

// CurrentUser context key to get current user from Request
const CurrentUser utils.ContextKey = "current_user"

// GetCurrentUser get current user from request
func (auth *Auth) GetCurrentUser(req *http.Request) interface{} {
	if currentUser := req.Context().Value(CurrentUser); currentUser != nil {
		return currentUser
	}

	claims, err := auth.SessionStorer.Get(req)
	if err == nil {
		context := &Context{Auth: auth, Claims: claims, Request: req}
		if user, err := auth.UserStorer.Get(claims, context); err == nil {
			return user
		}
	}

	return nil
}

// GetDB get db from request
func (auth *Auth) GetDB(request *http.Request) *gorm.DB {
	db := request.Context().Value(utils.ContextDBName)
	if tx, ok := db.(*gorm.DB); ok {
		return tx
	}
	return auth.Config.DB
}

// Login sign user in
func (auth *Auth) Login(claimer claims.ClaimerInterface, req *http.Request) error {
	return auth.SessionStorer.Update(claimer.ToClaims(), req)
}

// Logout sign current user out
func (auth *Auth) Logout(w http.ResponseWriter, req *http.Request) {
	auth.SessionStorer.Delete(req)
}
