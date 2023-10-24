package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv" // Import the strconv package
	"strings"
)

type updateRecordData struct {
	Domain string `json:"Domain"`
	IP     string `json:"Ip"`
}

func getConnIP(conn net.Conn) string {
	rawIP := conn.RemoteAddr().String()

	return splitRemoteAddr(rawIP)
}

func splitRemoteAddr(rawIP string) string {
	if strings.Index(rawIP, ":") != -1 {
		sip := strings.Split(rawIP, ":")
		if len(sip) != 2 {
			return rawIP
		}
		return sip[0]
	}
	return rawIP
}

func forbiddenResponse(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(403)
	w.Write([]byte(http.StatusText(403)))
}

func notFoundResponse(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(404)
	w.Write([]byte(http.StatusText(404)))
}

func updateRecordRequest(w http.ResponseWriter, r *http.Request) {
	// Get the API key from the request header
	apiKey := r.Header.Get("API-Key")

	// Check if the API key is valid
	if permission, ok := apiKeys[apiKey]; ok {
		// Valid API key found
		raddr := splitRemoteAddr(r.RemoteAddr)
		od := updateRecordData{}
		err := json.NewDecoder(r.Body).Decode(&od)
		if err != nil {
			forbiddenResponse(w, r)
			return
		}

		// Check if the API key has "write" permission to update records
		if permission == "update" {
			if od.IP == "" {
				if err := updateRecord(od.Domain, raddr, cbapiKey, performCallbackFlag); err != nil {
					w.Write([]byte(err.Error()))
					return
				}
			} else {
				if err := updateRecord(od.Domain, od.IP, cbapiKey, performCallbackFlag); err != nil {
					w.Write([]byte(err.Error()))
					return
				}
			}
			w.Write([]byte("UPDATE RECORD SUCCESS"))
		} else {
			// API key does not have "write" permission
			forbiddenResponse(w, r)
		}
	} else {
		// Invalid or missing API key
		forbiddenResponse(w, r)
	}
}

func deleteRecordRequest(w http.ResponseWriter, r *http.Request) {
	// Get the API key from the request header
	apiKey := r.Header.Get("API-Key")

	// Check if the API key is valid and has "delete" permission
	if permission, ok := apiKeys[apiKey]; ok && permission == "delete" {
		od := updateRecordData{}
		err := json.NewDecoder(r.Body).Decode(&od)

		if err != nil {
			forbiddenResponse(w, r)
			return
		}

		derr := deleteRecord(od.Domain, 1)

		if derr != nil {
			w.Write([]byte(derr.Error()))
			return
		}
		w.Write([]byte("DELETE RECORD SUCCESS"))
	} else {
		// Invalid or unauthorized API key
		forbiddenResponse(w, r)
	}
}

/**
*	webPageProc
**/
func webPageProc(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-control", "no-cache")

	// Parsing From Data
	r.ParseForm()
	defer func() {
		r.Body.Close()
	}()
	//

	switch r.URL.Path {
	case "/UPDATE":
		updateRecordRequest(w, r)
	case "/DELETE":
		deleteRecordRequest(w, r)
	default:
		forbiddenResponse(w, r)
	}
}

/**
*	wwwServ
**/
func wwwServ(servPort int) {
	fmt.Println("In wwwSServ handler ...") // Debug output
	http.HandleFunc("/", webPageProc)
	//
	servAddr := fmt.Sprintf(":%d", servPort)
	fmt.Println("wwwSServ port set ...") // Debug output
	err := http.ListenAndServe(servAddr, nil)

	if err != nil {
		fmt.Println("Error in wwwServ ...") // Debug output
		fmt.Println(err.Error())
		os.Exit(0)
	}
}

func wwwSServ(servPort int, certFile, keyFile string) {
	http.HandleFunc("/", webPageProc)

	// Start the HTTPS server
	err := http.ListenAndServeTLS(":"+strconv.Itoa(servPort), certFile, keyFile, nil)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
}
