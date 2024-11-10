package middleware

import (
	"fmt"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func AuthMiddleware(secretKey string) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")

		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token is missing"})
			c.Abort()
			return
		}

		// Parse the token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(secretKey), nil
		})

		if err != nil {

			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}

		if !token.Valid {

			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}

		// Set the token claims to the context
		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			log.Printf("Token claims: %v", claims)
			c.Set("claims", claims)
			if authID, ok := claims["auth_id"].(float64); ok {
				c.Set("auth_id", int64(authID))
			}
			if accountID, ok := claims["account_id"].(float64); ok {
				c.Set("account_id", int64(accountID))
			}
			if username, ok := claims["username"].(string); ok {
				c.Set("username", username)
			}
			log.Printf("Token parsing error: %v", err)
			log.Printf("Token valid: %v", token.Valid)
			log.Printf("Claims after parsing: %v", claims)

		} else {
			log.Printf("Invalid claims: %v", token.Claims)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}

		c.Next()
	}
}