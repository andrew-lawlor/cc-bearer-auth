package token

import (
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/andrew-lawlor/cc-bearer-auth/db"
)

var tokenCache = make(map[string]bool)

// LoadTokens loads tokens from the database into the cache.
func LoadTokens() error {
	db := db.GetDB()
	rows, err := db.Query("SELECT token FROM tokens")
	if err != nil {
		fmt.Println(err.Error())
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var token string
		if err := rows.Scan(&token); err != nil {
			fmt.Println(err.Error())
			return err
		}
		tokenCache[token] = true
	}

	if err := rows.Err(); err != nil {
		fmt.Println(err.Error())
		return err
	}

	log.Println("Tokens successfully loaded into cache.")
	return nil
}

func IsTokenValid(token string) bool {
	return tokenCache[token]
}

func BearerAuth(w http.ResponseWriter, r *http.Request) bool {
	authorization := r.Header.Get("Authorization")
	idToken := strings.TrimSpace(strings.Replace(authorization, "Bearer", "", 1))
	if IsTokenValid(idToken) {
		return true
	} else {
		http.Error(w, "Invalid token.", http.StatusUnauthorized)
		return false
	}
}
