package main

import (
	"fmt"
	"net/http"
	"log"
	"database/sql"
	"encoding/json"
	"math"
	"strconv"
	"unicode"
	"strings"

	"golang.org/x/crypto/bcrypt"
	_ "github.com/mattn/go-sqlite3"
)

var database *sql.DB

type Hash struct{}

type User struct {
	Name    string `json:"name"`
	Longtitude float64 `json:"longtitude"`
	Latitude float64 `json:"latitude"`
}

func verifyPassword(password string) error {
    var uppercasePresent bool
    var lowercasePresent bool
    var numberPresent bool
    var specialCharPresent bool
    const minPassLength = 8
    const maxPassLength = 64
    var passLen int
    var errorString string

    for _, ch := range password {
        switch {
        case unicode.IsNumber(ch):
            numberPresent = true
            passLen++
        case unicode.IsUpper(ch):
            uppercasePresent = true
            passLen++
        case unicode.IsLower(ch):
            lowercasePresent = true
            passLen++
        case unicode.IsPunct(ch) || unicode.IsSymbol(ch):
            specialCharPresent = true
            passLen++
        case ch == ' ':
            passLen++
        }
    }
    appendError := func(err string) {
        if len(strings.TrimSpace(errorString)) != 0 {
            errorString += ", " + err
        } else {
            errorString = err
        }
    }
    if !lowercasePresent {
        appendError("lowercase letter missing")
    }
    if !uppercasePresent {
        appendError("uppercase letter missing")
    }
    if !numberPresent {
        appendError("atleast one numeric character required")
    }
    if !specialCharPresent {
        appendError("special character missing")
    }
    if !(minPassLength <= passLen && passLen <= maxPassLength) {
        appendError(fmt.Sprintf("password length must be between %d to %d characters long", minPassLength, maxPassLength))
    }

    if len(errorString) != 0 {
        return fmt.Errorf(errorString)
    }
    return nil
}

func distance(lat1 float64, lng1 float64, lat2 float64, lng2 float64) float64 {
	const PI float64 = 3.141592653589793
	
	radlat1 := float64(PI * lat1 / 180)
	radlat2 := float64(PI * lat2 / 180)
	
	theta := float64(lng1 - lng2)
	radtheta := float64(PI * theta / 180)
	
	dist := math.Sin(radlat1) * math.Sin(radlat2) + math.Cos(radlat1) * math.Cos(radlat2) * math.Cos(radtheta)
	
	if dist > 1 {
		dist = 1
	}
	
	dist = math.Acos(dist)
	dist = dist * 180 / PI
	dist = dist * 60 * 1.1515
	
	dist = dist * 1.609344
	return dist
}

func services(w http.ResponseWriter, req *http.Request) {

	if req.URL.Path != "/people" {
		http.Error(w, "404 not found :/", http.StatusNotFound)
		return
	}

	switch req.Method {
	case "GET":

		if len(req.URL.Query().Get("longtitude")) == 0 || len(req.URL.Query().Get("latitude")) == 0 {
			fmt.Fprintf(w, "Missing parameter(s).")
			return
		}

		longtitude_query, err := strconv.ParseFloat(req.URL.Query().Get("longtitude"), 64)
		latitude_query, err := strconv.ParseFloat(req.URL.Query().Get("latitude"), 64)

		rows, _ := database.Query("SELECT * FROM people")
		users := []User{}

		var name string
		var longtitude, latitude float64

		for rows.Next() {

			err := rows.Scan(&name, &longtitude, &latitude)
			if err != nil {
				log.Fatal(err)
			}

			rows.Scan(&name, &longtitude, &latitude)
			km := distance(latitude, longtitude, latitude_query, longtitude_query)

			if km < 0.1{
				users = append(users, User{Name: name, Longtitude: longtitude, Latitude: latitude})
			}
		}
		
		response, err := json.Marshal(users)

		if err != nil {
			fmt.Println(err)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		w.Write(response)

	case "POST":

		if err := req.ParseForm(); err != nil {
			fmt.Fprintf(w, "ParseForm() err: %v", err)
			return
		}

		name := req.FormValue("name")
		longtitude := req.FormValue("longtitude")
		latitude := req.FormValue("latitude")
		newUser := req.FormValue("newUser")

		if newUser == "true" {
			statement, _ := database.Prepare("INSERT INTO people (name, longtitude, latitude) VALUES (?, ?, ?)")
			statement.Exec(name, longtitude, latitude)
			fmt.Fprintf(w, "New user added.")
		} else {
			statement, _ := database.Prepare("UPDATE people SET longtitude = ?, latitude = ? WHERE name = ?")
			statement.Exec(longtitude, latitude, name)
			fmt.Fprintf(w, "Existing user updated.")
		}

	default:
		fmt.Fprintf(w, "Please use GET/POST.\n")
	}
}

func signup(w http.ResponseWriter, req *http.Request) {

	if req.Method != "POST" {
		fmt.Fprintf(w, "Please use POST.\n")
		return
	}

	uName, email, pwd, pwdConfirm, dbName, dbMail := "", "", "", "", "", ""
 
	if err := req.ParseForm(); err != nil {
		fmt.Fprintf(w, "ParseForm() err: %v", err)
		return
	}

	uName = req.FormValue("username")
	email = req.FormValue("email")
	pwd = req.FormValue("password")
	pwdConfirm = req.FormValue("confirm")

	uNameCheck := len(uName)
	emailCheck := len(email)
	pwdCheck := len(pwd)
	pwdConfirmCheck := len(pwdConfirm)

	if uNameCheck == 0 || emailCheck == 0 || pwdCheck == 0 || pwdConfirmCheck == 0 {
		fmt.Fprintf(w, "Empty data.")
		return
	}

	if pwd == pwdConfirm {

		err := verifyPassword(pwd)
		if err != nil {
			fmt.Fprintf(w, err.Error())
			return
		}

		row_mail := database.QueryRow("SELECT email FROM users WHERE email = $1", email)
		row_mail.Scan(&dbMail)

		if dbMail != "" {
			fmt.Fprintf(w, "There is already an account associated with that email.")
			return
		}

		row_name := database.QueryRow("SELECT name FROM users WHERE name = $1", uName)
		row_name.Scan(&dbName)

		if dbName != ""{
			fmt.Fprintf(w, "Username already exists.")
			return
		}

		saltedBytes := []byte(pwd)
		hashedBytes, err := bcrypt.GenerateFromPassword(saltedBytes, bcrypt.DefaultCost)
		if err != nil {
			log.Fatal(err)
		}

		hash := string(hashedBytes[:])
		statement, _ := database.Prepare("INSERT INTO users (name, email, password) VALUES (?, ?, ?)")
		statement.Exec(uName, email, hash)
		fmt.Fprintf(w, "Registration successful!")

	} else {
		fmt.Fprintf(w, "Password information must be the same.")
	}
}

func login(w http.ResponseWriter, req *http.Request) {

	if req.Method != "POST" {
		fmt.Fprintf(w, "Please use POST.\n")
		return
	}
	
	email, pwd, dbPwd := "", "", ""

	req.ParseForm()
	email = req.FormValue("email")  
	pwd = req.FormValue("password") 

	emailCheck := len(email)
	pwdCheck := len(pwd)

	if emailCheck == 0 || pwdCheck == 0 {
		fmt.Fprintf(w, "Empty data.")
		return
	}

	row := database.QueryRow("SELECT password FROM users WHERE email = $1", email)
	err := row.Scan(&dbPwd)

	if err != nil {
		if err == sql.ErrNoRows {
			fmt.Fprintf(w, "User not found.")
			return
		} else {
			panic(err)
		}
	}
	
	incoming := []byte(pwd)
	existing := []byte(dbPwd)
	hashed := bcrypt.CompareHashAndPassword(existing, incoming)

	if hashed == nil {
		fmt.Fprintf(w, "Login succesful!")
	} else {
		fmt.Fprintf(w, "Login failed.")
	}

}

func headers(w http.ResponseWriter, req *http.Request) {

	for name, headers := range req.Header {
		for _, h := range headers {
			fmt.Fprintf(w, "%v: %v\n", name, h)
		}
	}
}

func staticFiles(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "./static/"+r.URL.Path)
}

func main() {

	// CREATE sqlite3 database.
	database, _ = sql.Open("sqlite3", "./database.db")
	statement1, _ := database.Prepare("CREATE TABLE IF NOT EXISTS people (name TEXT, longtitude TEXT, latitude TEXT)")
	statement2, _ := database.Prepare("CREATE TABLE IF NOT EXISTS users (name TEXT, email TEXT, password TEXT)")
	statement1.Exec()
	statement2.Exec()

	http.HandleFunc("/people", services)
	http.HandleFunc("/signup", signup)
	http.HandleFunc("/login", login)
	http.HandleFunc("/", staticFiles)
	port := ":8090"

	//http.HandleFunc("/headers", headers)

	fmt.Println("Starting server for listening on port", port)
	if err := http.ListenAndServe(port, nil); err != nil{
		log.Fatal(err)
	}
}
