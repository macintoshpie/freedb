package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"time"

	"github.com/gorilla/mux"
	_ "github.com/mattn/go-sqlite3"
)

const USER_DB_PATH = "user_dbs"

func checkErr(err error) {
	if err != nil {
		log.Println("ERROR: ")
		log.Println(err)
		panic(err)
	}
}

func assertAvailablePRNG() {
	buf := make([]byte, 1)

	_, err := io.ReadFull(rand.Reader, buf)
	if err != nil {
		panic(fmt.Sprintf("crypto/rand is unavailable: Read() failed with %#v", err))
	}
}

func GenerateRandomString(n int) (string, error) {
	// source: https://gist.github.com/dopey/c69559607800d2f2f90b1b1ed4e550fb
	const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-"
	ret := make([]byte, n)
	for i := 0; i < n; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			return "", err
		}
		ret[i] = letters[num.Int64()]
	}

	return string(ret), nil
}

func dbExists(dbName string) (bool, error) {
	if _, err := os.Stat(dbName); err == nil {
		return true, nil
	} else if os.IsNotExist(err) {
		return false, nil
	} else {
		return false, err
	}
}

func getDBName(dbToken string) (string, error) {
	matched, err := regexp.Match(`^[a-zA-Z0-9\-]{32}$`, []byte(dbToken))
	checkErr(err)

	if !matched {
		return "", errors.New("Invalid token")
	}

	return fmt.Sprintf("%s/%s.db", USER_DB_PATH, dbToken), nil
}

func ScanRows(rows *sql.Rows) ([]map[string]interface{}, error) {
	// source: https://www.farrellit.net/2018/08/12/golang-sql-unknown-rows.html
	cols, err := rows.Columns()
	checkErr(err)
	// we"ll want to end up with a list of name->value maps, a la JSON
	// surely we know how many rows we got but can"t find it now
	allgeneric := make([]map[string]interface{}, 0)
	// we"ll need to pass an interface to sql.Row.Scan
	colvals := make([]interface{}, len(cols))
	for rows.Next() {
		colassoc := make(map[string]interface{}, len(cols))
		// values we"ll be passing will be pointers, themselves to interfaces
		for i, _ := range colvals {
			colvals[i] = new(interface{})
		}
		err := rows.Scan(colvals...)
		if err != nil {
			return []map[string]interface{}{}, err
		}

		for i, col := range cols {
			colassoc[col] = *colvals[i].(*interface{})
		}
		allgeneric = append(allgeneric, colassoc)
	}

	return allgeneric, nil
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println(r.RequestURI)
		next.ServeHTTP(w, r)
	})
}

func headerMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		next.ServeHTTP(w, r)
	})
}

// access control and  CORS middleware
func accessControlMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Origin, Content-Type")
		if r.Method == "OPTIONS" {
			return
		}

		next.ServeHTTP(w, r)
	})
}

type QueryRequest struct {
	Token  string        `json:"token"`
	Query  string        `json:"query"`
	Params []interface{} `json:"params,omitempty"`
}

func ErrorResponse(w http.ResponseWriter, error_message string, status_code int) {
	error_res := map[string]string{}
	error_res["error"] = error_message
	bytes, err := json.MarshalIndent(error_res, "", "    ")
	checkErr(err)

	http.Error(w, string(bytes), status_code)
}

func JsonResponse(w http.ResponseWriter, json_body interface{}, status_code int) {
	bytes, err := json.MarshalIndent(json_body, "", "    ")
	checkErr(err)

	w.WriteHeader(status_code)
	w.Write(bytes)
}

func cleanQuery(query string) string {
	re := regexp.MustCompile(`(?s)(/\*.*?\*/)`)
	query = re.ReplaceAllString(query, "")

	re = regexp.MustCompile(`\-\-.*$`)
	query = re.ReplaceAllString(query, "")

	return strings.TrimSpace(query)
}

func QueryHandler(w http.ResponseWriter, r *http.Request) {
	byteValue, _ := ioutil.ReadAll(r.Body)

	var req QueryRequest
	err := json.Unmarshal(byteValue, &req)
	if err != nil {
		ErrorResponse(w, "Bad request", 400)
		return
	}

	if len(cleanQuery(req.Query)) == 0 {
		ErrorResponse(w, "Missing query", 400)
		return
	}

	dbName, err := getDBName(req.Token)
	if err != nil {
		ErrorResponse(w, "Invalid token", 400)
		return
	}

	exists, err := dbExists(dbName)
	checkErr(err)

	if !exists {
		ErrorResponse(w, "Invalid token", 400)
		return
	}

	db, err := sql.Open("sqlite3", dbName)
	checkErr(err)
	var rows *sql.Rows
	if req.Params != nil {
		stmt, err := db.Prepare(req.Query)
		if err != nil {
			ErrorResponse(w, err.Error(), 400)
			return
		}

		rows, err = stmt.Query(req.Params...)
		if err != nil {
			ErrorResponse(w, err.Error(), 400)
			return
		}
	} else {
		rows, err = db.Query(req.Query)
		if err != nil {
			ErrorResponse(w, err.Error(), 400)
			return
		}
	}
	defer rows.Close()

	scannedRows, err := ScanRows(rows)
	checkErr(err)

	j, err := json.Marshal(scannedRows)
	checkErr(err)

	w.Write(j)
}

func DBCreateHandler(w http.ResponseWriter, r *http.Request) {
	dbToken, err := GenerateRandomString(32)
	checkErr(err)

	dbName, err := getDBName(dbToken)
	checkErr(err)

	db, err := sql.Open("sqlite3", dbName)
	checkErr(err)

	err = db.Ping()
	checkErr(err)

	response := map[string]string{}
	response["token"] = dbToken
	JsonResponse(w, response, 200)
}

func main() {
	if _, err := os.Stat(USER_DB_PATH); os.IsNotExist(err) {
		err := os.Mkdir(USER_DB_PATH, 0777)
		checkErr(err)
	}

	assertAvailablePRNG()

	var wait time.Duration
	flag.DurationVar(&wait, "graceful-timeout", time.Second*15, "the duration for which the server gracefully wait for existing connections to finish - e.g. 15s or 1m")
	flag.Parse()

	// create router and server
	r := mux.NewRouter()
	r.HandleFunc("/db", DBCreateHandler).Methods(http.MethodPost, http.MethodOptions)
	r.HandleFunc("/q", QueryHandler).Methods(http.MethodPost, http.MethodOptions)
	r.Use(mux.CORSMethodMiddleware(r))
	r.Use(loggingMiddleware)
	r.Use(accessControlMiddleware)
	r.Use(headerMiddleware)

	srv := &http.Server{
		Handler:      r,
		Addr:         "127.0.0.1:8000",
		WriteTimeout: 2 * time.Second,
		ReadTimeout:  2 * time.Second,
	}

	// Run our server in a goroutine so that it doesn't block.
	go func() {
		log.Println("Starting server...")
		if err := srv.ListenAndServe(); err != nil {
			log.Println(err)
		}
	}()

	c := make(chan os.Signal, 1)
	// We'll accept graceful shutdowns when quit via SIGINT (Ctrl+C)
	// SIGKILL, SIGQUIT or SIGTERM (Ctrl+/) will not be caught.
	signal.Notify(c, os.Interrupt)

	// Block until we receive our signal.
	<-c

	// Create a deadline to wait for.
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	// Doesn't block if no connections, but will otherwise wait
	// until the timeout deadline.
	srv.Shutdown(ctx)
	// Optionally, you could run srv.Shutdown in a goroutine and block on
	// <-ctx.Done() if your application should wait for other services
	// to finalize based on context cancellation.
	log.Println("shutting down")
	os.Exit(0)
}
