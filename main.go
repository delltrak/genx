package genx

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/golang-jwt/jwt"
)

/*
	SecureHandlerFunc is a middleware that checks if the request has a valid token

and if the token has the correct command claim
wich pass handlerFunc and secretKey as parameters
*/
func Secure(handlerFunc http.Handler, secretKey string) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		ip := r.RemoteAddr
		browser := r.UserAgent()
		method := r.Method
		path := r.URL.Path

		log.Printf("\033[30m==============================================\033[0m")
		log.Printf("\033[34;1mRequest: %s %s, IP: %s, Browser: %s\033[0m", method, path, ip, browser)

		// log body of the request
		bodyBytes, err := ioutil.ReadAll(r.Body)
		if err != nil {
			log.Fatal(err)
		}
		bodyString := string(bodyBytes)
		log.Printf("\033[30;1mBody: %s\033[0m", bodyString)

		// pega o bearer token
		bearerToken := r.Header.Get("Authorization")

		// verifica se o token está presente
		if bearerToken == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintf(w, `{ "success": false, "message": "Token não encontrado!" }`)
			// log in red color message token not found
			log.Printf("\033[31m🚨 Bearer token not found, request was rejected!\033[0m")
			return
		}

		bearerToken = bearerToken[len("Bearer "):]

		// verifica se o token é valido
		token, err := jwt.Parse(bearerToken, func(token *jwt.Token) (interface{}, error) {
			// verifica se o token é valido
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {

				return nil, fmt.Errorf("Erro ao validar o token!")
			}
			return []byte(secretKey), nil
		})

		// verifica se o token é valido
		if err != nil {

			// response in json
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			log.Printf("\033[31m🚨 Erro ao verificar token.\033[0m")
			fmt.Fprintf(w, `{ "success": false, "message": "Token inválido!" }`)
			return
		}

		// verifica se o token é valido
		if !token.Valid {

			// response in json
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			log.Printf("\033[31m🚨 Token inválido.\033[0m")
			fmt.Fprintf(w, `{ "success": false, "message": "Token inválido!" }`)
			return
		}

		/* // get claims
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			log.Printf("\033[31m🚨 Erro ao obter claims.\033[0m")
			return
		}

		command, ok := claims["command"].(string)
		if !ok {
			log.Println("Invalid or missing command claim")
			return
		}
		log.Printf("\033[32mCommand: %s\033[0m", command)*/

		// chama o proximo handler
		handlerFunc.ServeHTTP(w, r)
	})
}
