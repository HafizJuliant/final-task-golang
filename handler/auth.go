package handler

import (
	"final-task-golang/model"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type AuthInterface interface {
	Login(*gin.Context)
	Upsert(*gin.Context)
	ChangePassword(c *gin.Context)
}

type authImplement struct {
	db         *gorm.DB
	signingKey []byte
}

func NewAuth(db *gorm.DB, signingKey []byte) AuthInterface {
	return &authImplement{
		db,
		signingKey,
	}
}

type authLoginPayload struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (a *authImplement) Login(c *gin.Context) {
	payload := authLoginPayload{}

	// parsing JSON payload to struct model
	err := c.BindJSON(&payload)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": err,
		})
		return
	}

	// Validate username to get auth data
	auth := model.Auth{}
	if err := a.db.Where("username = ?",
		payload.Username).
		First(&auth).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error": "wrong username",
			})
			return
		}

		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	// Validate password
	if err := bcrypt.CompareHashAndPassword([]byte(auth.Password), []byte(payload.Password)); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": "wrong password",
		})
		return
	}

	// Login is valid
	token, err := a.createJWT(&auth)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"error": err,
		})
		return
	}

	// c.SetSameSite(http.SameSiteLaxMode) // Set SameSite attribute (for cross-origin requests)
	// c.SetCookie("auth_token", token, 3600*72, "/", "", false, true)

	// Success response
	c.JSON(http.StatusOK, gin.H{
		"message": fmt.Sprintf("%v Login succes", payload.Username),
		"data":    token,
	})
}

type authUpsertPayload struct {
	AccountID int64  `json:"account_id"`
	Username  string `json:"username"`
	Password  string `json:"password"`
}

func (a *authImplement) Upsert(c *gin.Context) {
	payload := authUpsertPayload{}

	// parsing JSON payload to struct model
	err := c.BindJSON(&payload)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": err,
		})
		return
	}

	// Hash Given Password
	hashed, err := bcrypt.GenerateFromPassword([]byte(payload.Password), bcrypt.DefaultCost)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": err,
		})
		return
	}

	// Check AccountID is valid
	var account model.Account
	if err := a.db.First(&account, payload.AccountID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{
				"error": "Account Not found",
			})
			return
		}

		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	// Prepare new auth data with new password
	auth := model.Auth{
		AccountID: payload.AccountID,
		Username:  payload.Username,
		Password:  string(hashed),
	}

	// Upsert auth data (Insert or Update if already exists)
	result := a.db.Clauses(
		clause.OnConflict{
			DoUpdates: clause.AssignmentColumns([]string{"username", "password"}),
			Columns:   []clause.Column{{Name: "account_id"}},
		}).Create(&auth)
	if result.Error != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": result.Error.Error(),
		})
		return
	}

	// Success response
	c.JSON(http.StatusOK, gin.H{
		"message": "Create success",
		"data":    payload.Username,
	})
}
func (a *authImplement) ChangePassword(c *gin.Context) {

	var changePasswordPayload struct {
		NewPassword        string `json:"new_password"`
		ConfirmNewPassword string `json:"confirm_new_password"`
	}

	payload := changePasswordPayload

	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload"})
		return
	}

	if payload.NewPassword != payload.ConfirmNewPassword {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Passwords do not match"})
		return
	}

	// Get account_id and username from the token claims
	claims, _ := c.Get("claims")
	userClaims := claims.(jwt.MapClaims)
	accountID := int64(userClaims["account_id"].(float64))
	username := userClaims["username"].(string)

	// Hash the new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(payload.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	// Create an authUpsertPayload struct with the new password and call Upsert
	upsertPayload := authUpsertPayload{
		AccountID: accountID,
		Username:  username,
		Password:  string(hashedPassword),
	}

	// Set up the request context with the new payload and call the Upsert method
	c.Set("upsertPayload", upsertPayload)
	a.Upsert(c)
}

/*if err := c.ShouldBindJSON(&payload); err != nil {
	c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload"})
	return
}

// Check if the new password matches confirmation
if payload.NewPassword != payload.ConfirmNewPassword {
	c.JSON(http.StatusBadRequest, gin.H{"error": "Passwords do not match"})
	return
}

// Retrieve the username and account_id from the token claims
claims, exists := c.Get("claims")
log.Printf("Claims retrieved: %v", claims)

if !exists {
	c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
	return
}
userClaims := claims.(jwt.MapClaims)
accountID := int64(userClaims["account_id"].(float64))
username := userClaims["username"].(string)
log.Printf("Username from claims: %v", userClaims["username"])
// Validate that the user exists in the database
var auth model.Auth
if err := a.db.Where("account_id = ? AND username = ?", accountID, username).First(&auth).Error; err != nil {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
	return
}

// Hash the new password
hashedPassword, err := bcrypt.GenerateFromPassword([]byte(payload.NewPassword), bcrypt.DefaultCost)
if err != nil {
	c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
	return
}

// Update the password in the database
if err := a.db.Model(&model.Auth{}).Where("account_id = ?", accountID).
	Update("password", string(hashedPassword)).Error; err != nil {
	c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update password"})
	return
}

c.JSON(http.StatusOK, gin.H{"message": "Password updated successfully"})*/

func (a *authImplement) createJWT(auth *model.Auth) (string, error) {
	// Create the jwt token signer
	token := jwt.New(jwt.SigningMethodHS256)

	// Add claims data or additional data (avoid to put secret information in the payload or header elements)
	claims := token.Claims.(jwt.MapClaims)
	claims["auth_id"] = auth.AuthID
	claims["account_id"] = auth.AccountID
	claims["username"] = auth.Username
	claims["exp"] = time.Now().Add(time.Hour * 72).Unix() // Token expires in 72 hours

	// Encode
	tokenString, err := token.SignedString(a.signingKey)
	if err != nil {
		return "", err
	}

	// Return the token
	return tokenString, nil
}