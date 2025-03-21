package main

import (
	"bufio"
	"bytes"         // Import the bytes package
	"encoding/json" // Import the json package
	"errors"
	"flag"
	"fmt"
	"math"
	"net"
	"net/http" // Import the http package
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

var (
	port                *int
	wwwport             *int
	callbackURL         string
	cbapiKey            string
	useHTTPS            *int
	certFile            *string // Add a flag for the certificate file path
	keyFile             *string // Add a flag for the key file path
	dnsMap              map[string]string
	performCallbackFlag int    // Declare performCallbackFlag as a package-level variable
	callbackURLFlag     string // Declare callbackURLFlag as a package-level variable
	dnsMutex            sync.Mutex
)

// Define apiKeys as a package-level variable
var apiKeys = map[string]string{
	os.Getenv("UPDATEAPIKEY"): "update",
	os.Getenv("DELETEAPIKEY"): "delete",
}

var callbackAPIKey = os.Getenv("CALLBACKAPIKEY")

func getFirstIPv6Address() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		fmt.Println("Error while getting network interfaces:", err)
		return ""
	}

	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			fmt.Println("Error while getting addresses for interface", iface.Name, ":", err)
			continue
		}

		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() == nil && ipnet.IP.IsGlobalUnicast() {
					// Found a global IPv6 address on the interface
					return ipnet.IP.String()
				}
			}
		}
	}

	// No global IPv6 address found
	return ""
}

func getFirstEthernetIPv4() (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 && iface.Flags&net.FlagPointToPoint == 0 {
			addrs, err := iface.Addrs()
			if err != nil {
				return "", err
			}

			for _, addr := range addrs {
				ipnet, ok := addr.(*net.IPNet)
				if ok && ipnet.IP.To4() != nil {
					return ipnet.IP.String(), nil
				}
			}
		}
	}

	return "", fmt.Errorf("No IPv4 address found on any Ethernet interface")
}

func saveRecord() error {
	f, ferr := os.OpenFile(".\\ddns.dat", os.O_CREATE|os.O_WRONLY, 0644)

	if ferr != nil {
		return ferr
	}

	var rcnt int

	defer func() {
		f.Close()

		if rcnt == 0 {
			os.Remove(".\\ddns.dat")
		}
	}()

	for _, v := range dnsMap {
		f.Write([]byte(v + "\n"))
		rcnt++
	}
	return nil
}

func loadRecord() error {
	file, err := os.Open(".\\ddns.dat")

	if err != nil {
		return err
	}

	defer file.Close()

	scan := bufio.NewScanner(file)

	for scan.Scan() {

		rd := scan.Text()

		if rd != "" {
			rr, rrerr := dns.NewRR(rd)

			if rrerr == nil {
				key, kerr := getKey(rr.(dns.RR).Header().Name, 1)
				if kerr == nil {
					dnsMap[key] = rd
				}
			}
		}
	}

	err = scan.Err()

	if err != nil {
		fmt.Println(err.Error())
	}
	return nil
}

func getKey(domain string, rtype uint16) (r string, e error) {
	if n, ok := dns.IsDomainName(domain); ok {
		labels := dns.SplitDomainName(domain)

		// Reverse domain, starting from top-level domain
		// eg.  ".com.mkaczanowski.test "
		var tmp string
		for i := 0; i < int(math.Floor(float64(n/2))); i++ {
			tmp = labels[i]
			labels[i] = labels[n-1]
			labels[n-1] = tmp
		}

		reverse_domain := strings.Join(labels, ".")
		r = strings.Join([]string{reverse_domain, strconv.Itoa(int(rtype))}, "_")
	} else {
		e = errors.New("Invailid domain: " + domain)
		fmt.Println(e.Error())
	}

	return r, e
}

func deleteRecord(domain string, rtype uint16) (err error) {

	dnsMutex.Lock()
	defer dnsMutex.Unlock()

	key, kerr := getKey(domain, rtype)

	if kerr != nil {
		return kerr
	}

	_, exists := dnsMap[key]

	if exists {
		delete(dnsMap, key)
	} else {
		e := errors.New("Delete record failed for domain:  " + domain)
		fmt.Println(e.Error())
		return e
	}

	fmt.Println("Delete Record", "-", domain)

	saveRecord()

	return nil
}

func updateRecord(domain, ipaddr, callbackAPIKey string, performCallbackFlag int) error {
	// Create a new A record with the new IP address
	rr := new(dns.A)
	rr.A = net.ParseIP(ipaddr)
	rr.Hdr.Name = domain
	rr.Hdr.Class = dns.ClassINET
	rr.Hdr.Rrtype = dns.TypeA
	rr.Hdr.Ttl = 30

	// Store the updated record
	err := storeRecord(rr)
	if err != nil {
		return err
	}

	// Only perform the callback if performCallbackFlag is 1 and there is no error in updating the record
	if performCallbackFlag == 1 {
		currentIP, getCurrentErr := getCurrentIP(domain)
		if getCurrentErr != nil {
			return getCurrentErr
		}

		// Perform the callback with the API key, old IP, and new IP
		callbackErr := performCallback(callbackAPIKey, currentIP, ipaddr, callbackURL)
		if callbackErr != nil {
			return callbackErr
		}
	}

	return nil
}

func storeRecord(rr dns.RR) (err error) {
	dnsMutex.Lock()
	defer dnsMutex.Unlock()

	key, kerr := getKey(rr.Header().Name, rr.Header().Rrtype)

	if kerr != nil {
		return kerr
	}

	dnsMap[key] = rr.String()

	saveRecord()

	return nil
}

func getRecord(domain string, rtype uint16) (rr dns.RR, err error) {

	key, kerr := getKey(domain, rtype)

	if kerr != nil {
		return nil, kerr
	}

	v, exists := dnsMap[key]

	if exists {
		if v == "" {
			e := errors.New("Record not found, key:  " + key)
			fmt.Println(e.Error())

			return nil, e
		}

		rr, err = dns.NewRR(v)

		if err != nil {
			return nil, err
		}

		return rr, nil
	} else {
		e := errors.New("Record not found, key:  " + key)
		fmt.Println(e.Error())

		return nil, e
	}
}

func newRecordA(domain, ipaddr string) {

	rr := new(dns.A)

	rr.A = net.ParseIP(ipaddr)
	rr.Hdr.Name = domain
	rr.Hdr.Class = dns.ClassINET
	rr.Hdr.Rrtype = 1 // A
	rr.Hdr.Ttl = 30

	storeRecord(rr)
}

func parseQuery(m *dns.Msg) {
	var rr dns.RR

	for _, q := range m.Question {
		if read_rr, e := getRecord(q.Name, q.Qtype); e == nil {
			rr = read_rr.(dns.RR)
			if rr.Header().Name == q.Name {
				m.Answer = append(m.Answer, rr)
			}
		}
	}
}

func handleDnsRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	switch r.Opcode {
	case dns.OpcodeQuery:
		parseQuery(m)
	}
	w.WriteMsg(m)
}

func serve(bindAddr string, ipv6Addr string, port int) {
	// Create a separate instance of dns.Server for each listener
	ipv4Server := &dns.Server{Addr: bindAddr + ":" + strconv.Itoa(port), Net: "udp"}
	// ipv6Server := &dns.Server{Addr: ipv6Addr + ":" + strconv.Itoa(port), Net: "udp"}

	// Start the IPv4 listener in a goroutine
	go func() {
		fmt.Println("Starting IPv4 listener")
		err := ipv4Server.ListenAndServe()
		if err != nil {
			fmt.Println("Failed to set up the IPv4 udp server:", err.Error())
		}
	}()

	// Start the IPv6 listener in a separate goroutine
	// go func() {
	// 	fmt.Println("Starting IPv6 listener")
	// 	err := ipv6Server.ListenAndServe()
	// 	if err != nil {
	// 		fmt.Println("Failed to set up the IPv6 udp server:", err.Error())
	// 	}
	// }()

	select {}
}

func performCallback(apiKey, oldIP, newIP, callbackURL string) error {
	// Define the JSON payload for the callback
	payload := map[string]string{
		"ApiKey": apiKey,
		"OldIP":  oldIP,
		"NewIP":  newIP,
	}

	// Convert the payload to JSON
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	// Perform the HTTP POST request to the provided callback URL
	resp, err := http.Post(callbackURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Check the response status code (e.g., 200 for success)
	if resp.StatusCode != http.StatusOK {
		return errors.New("Callback failed with status code: " + resp.Status)
	}

	return nil
}

func getCurrentIP(domain string) (string, error) {
	rr, err := getRecord(domain, dns.TypeA)
	if err != nil {
		return "", err
	}

	if a, ok := rr.(*dns.A); ok {
		return a.A.String(), nil
	}

	return "", errors.New("DNS record is not of type A")
}

func main() {
	fmt.Println("Starting program...") // Debug output
	dnsMap = make(map[string]string)
	loadRecord()
	// Get the first available Ethernet IPv4 address
	bindAddr, err := getFirstEthernetIPv4()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	// Get the IPv6 address of the first available network interface
	ipv6Addr := getFirstIPv6Address()

	// Check if we found an IPv6 address
	if ipv6Addr == "" {
		fmt.Println("No global IPv6 address found on any network interface.")
		return
	}

	// Print the bound address
	fmt.Println("Binding to:", bindAddr)
	fmt.Println("Binding to:", ipv6Addr)
	// Parse flags
	port = flag.Int("port", 53, "server port (dns server)")
	wwwport = flag.Int("cport", 8080, "control port (httpd)")
	performCallbackFlag = *flag.Int("performcallback", 0, "Perform callback if set to 1")
	callbackURLFlag := flag.String("callbackurl", "https://example.com/callback", "Callback URL")
	certFile = flag.String("cert", "cert.pem", "Path to the certificate file")
	keyFile = flag.String("key", "key.pem", "Path to the private key file")
	useHTTPS = flag.Int("useHTTPS", 0, "use HTTPS (1) or HTTP (0)")

	flag.Parse()
	fmt.Println("Parsed flags, starting services...") // Debug output

	callbackURL = *callbackURLFlag

	// Attach request handler func
	fmt.Println("DNS handler starting...") // Debug output

	dns.HandleFunc(".", handleDnsRequest)

	// Start server based on useHTTPS flag
	if *useHTTPS == 1 {
		if *certFile == "" || *keyFile == "" {
			fmt.Println("Please provide both certificate and key files when using HTTPS.")
			os.Exit(1)
		}
		fmt.Println("wwwSServ handler starting...") // Debug output
		go wwwSServ(*wwwport, *certFile, *keyFile)
	} else {
		fmt.Println("wwwServ handler starting...") // Debug output
		go wwwServ(*wwwport, bindAddr)
	}
	// Start server
	serve(bindAddr, ipv6Addr, *port)
}
