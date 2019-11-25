package main

import (
	"bytes"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"
)

// Console flags
var (
	listen                = flag.String("l", ":8888", "port to accept requests")
	targetProduction      = flag.String("a", "localhost:8080", "where production traffic goes. http://localhost:8080/production")
	debug                 = flag.Bool("debug", false, "more logging, showing ignored output")
	productionTimeout     = flag.Int("a.timeout", 2500, "timeout in milliseconds for production traffic")
	alternateTimeout      = flag.Int("b.timeout", 1000, "timeout in milliseconds for alternate site traffic")
	productionHostRewrite = flag.Bool("a.rewrite", false, "rewrite the host header when proxying production traffic")
	alternateHostRewrite  = flag.Bool("b.rewrite", false, "rewrite the host header when proxying alternate site traffic")
	percent               = flag.Float64("p", 100.0, "float64 percentage of traffic to send to testing")
	tlsPrivateKey         = flag.String("key.file", "", "path to the TLS private key file")
	tlsCertificate        = flag.String("cert.file", "", "path to the TLS certificate file")
	forwardClientIP       = flag.Bool("forward-client-ip", false, "enable forwarding of the client IP to the backend using the 'X-Forwarded-For' and 'Forwarded' headers")
	closeConnections      = flag.Bool("close-connections", false, "close connections to the clients and backends")
	searchValue           = flag.String("search-value", "", "A search value that, if found in the inbound message will allow the B system to reply.")
	configFile            = flag.String("config-file", "", "A config file that has defined routes for systems based on search and/or URL parameters.")
)

// keeps track of the urls
var systemMap map[string]string

// Sets the request URL.
//
// This turns a inbound request (a request without URL) into an outbound request.
func setRequestTarget(request *http.Request, target string, scheme string) {
	URL, err := url.Parse(scheme + "://" + target + request.URL.String())
	if err != nil {
		log.Println(err)
	}
	request.URL = URL
}

func getTransport(scheme string, timeout time.Duration) (transport *http.Transport) {
	if scheme == "https" {
		transport = &http.Transport{
			Dial: (&net.Dialer{ // go1.8 deprecated: Use DialContext instead
				Timeout:   timeout,
				KeepAlive: 10 * timeout,
			}).Dial,
			DisableKeepAlives:     *closeConnections,
			TLSHandshakeTimeout:   timeout,
			ResponseHeaderTimeout: timeout,
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		}
	} else {
		transport = &http.Transport{
			Dial: (&net.Dialer{ // go1.8 deprecated: Use DialContext instead
				Timeout:   timeout,
				KeepAlive: 10 * timeout,
			}).Dial,
			DisableKeepAlives:     *closeConnections,
			TLSHandshakeTimeout:   timeout,
			ResponseHeaderTimeout: timeout,
		}
	}
	return
}

// handleAlternativeRequest duplicate request and sent it to alternative backend
func handleAlternativeRequest(request *http.Request, timeout time.Duration, scheme string) {

	defer func() {
		if r := recover(); r != nil && *debug {
			log.Println("Recovered in ServeHTTP(alternate request) from:", r)
		}
	}()
	response := handleRequest(request, timeout, scheme)

	if response != nil {
		response.Body.Close()
	}
}

// inspects the body
func getBody(request *http.Request) []byte {
	var bodyCopy []byte
	var err error
	if request.Body != nil {
		bodyCopy, err = ioutil.ReadAll(request.Body)
		if err == nil {
			restoreBody(request, bodyCopy)
		}
	}
	return bodyCopy
}

// restores the request buffer
func restoreBody(request *http.Request, bodyCopy []byte) {
	body := make([]byte, len(bodyCopy))
	copy(body, bodyCopy)
	request.Body = ioutil.NopCloser(bytes.NewBuffer(body))
}

func checkForString(body []byte, checkVal string) bool {
	var searchable string
	// convert the body to a string
	body = []byte(string(body))
	// perform the search
	searchable = string(body)
	return strings.Contains(searchable, checkVal)
}

// Sends a request and returns the response.
func handleRequest(request *http.Request, timeout time.Duration, scheme string) *http.Response {
	transport := getTransport(scheme, timeout)
	response, err := transport.RoundTrip(request)
	if err != nil {
		log.Println("Request failed:", err)
	}
	return response
}

// SchemeAndHost parse URL into scheme and rest of endpoint
func SchemeAndHost(url string) (scheme, hostname string) {
	if strings.HasPrefix(url, "https") {
		hostname = strings.TrimPrefix(url, "https://")
		scheme = "https"
	} else {
		hostname = strings.TrimPrefix(url, "http://")
		scheme = "http"
	}
	return
}

// handler contains the address of the main Target and the one for the Alternative target
type handler struct {
	Target       string
	TargetScheme string
	Alternatives []backend
	Randomizer   rand.Rand
}

type backend struct {
	Alternative       string
	AlternativeScheme string
}

type arrayAlternatives []backend

func (i *arrayAlternatives) String() string {
	return "my string representation"
}

func (i *arrayAlternatives) Set(value string) error {
	scheme, endpoint := SchemeAndHost(value)
	altServer := backend{AlternativeScheme: scheme, Alternative: endpoint}
	*i = append(*i, altServer)
	return nil
}

func (h *handler) SetSchemes() {
	h.TargetScheme, h.Target = SchemeAndHost(h.Target)
}

// ServeHTTP duplicates the incoming request (req) and does the request to the
// Target and the Alternate target discading the Alternate response
func (h handler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	var alternativeRequest *http.Request
	var productionRequest *http.Request
	var altHost string
	var altScheme string

	body := getBody(req)
	flip := checkForString(body, *searchValue)

	if flip {
		log.Println("we found the search pattern...flipping the a to the b system.")
	}

	if *forwardClientIP {
		updateForwardedHeaders(req)
	}

	if *percent == 100.0 || h.Randomizer.Float64()*100 < *percent {
		for _, alt := range h.Alternatives {
			alternativeRequest = DuplicateRequest(req)
			altHost = alt.Alternative
			altScheme = alt.AlternativeScheme

			timeout := time.Duration(*alternateTimeout) * time.Millisecond

			if flip {
				setRequestTarget(alternativeRequest, h.Target, h.TargetScheme)
			} else {
				setRequestTarget(alternativeRequest, alt.Alternative, alt.AlternativeScheme)
			}

			if *alternateHostRewrite {
				alternativeRequest.Host = alt.Alternative
			}
			if flip != true {
				go handleAlternativeRequest(alternativeRequest, timeout, alt.AlternativeScheme)
			}
		}
	}

	productionRequest = req
	defer func() {
		if r := recover(); r != nil && *debug {
			log.Println("Recovered in ServeHTTP(production request) from:", r)
		}
	}()

	if flip == true {
		setRequestTarget(productionRequest, altHost, altScheme)
	} else {
		setRequestTarget(productionRequest, h.Target, h.TargetScheme)
	}

	if *productionHostRewrite {
		productionRequest.Host = h.Target
	}

	timeout := time.Duration(*productionTimeout) * time.Millisecond
	resp := handleRequest(productionRequest, timeout, h.TargetScheme)

	if resp != nil {
		defer resp.Body.Close()

		// Forward response headers.
		for k, v := range resp.Header {
			w.Header()[k] = v
		}
		w.WriteHeader(resp.StatusCode)

		// Forward response body.
		io.Copy(w, resp.Body)
	}
}

func main() {
	var altServers arrayAlternatives
	flag.Var(&altServers, "b", "where testing traffic goes. response are skipped. http://localhost:8081/test, allowed multiple times for multiple testing backends")
	flag.Parse()

	log.Printf("Starting teeproxy at %s sending to A: %s and B: %s",
		*listen, *targetProduction, altServers)

	if *configFile != "" {
		log.Printf("Looking for a config file at %s", *configFile)
		readConfigFile(configFile)
	}

	runtime.GOMAXPROCS(runtime.NumCPU())

	var err error

	var listener net.Listener

	if len(*tlsPrivateKey) > 0 {
		cer, err := tls.LoadX509KeyPair(*tlsCertificate, *tlsPrivateKey)
		if err != nil {
			log.Fatalf("Failed to load certficate: %s and private key: %s", *tlsCertificate, *tlsPrivateKey)
		}

		config := &tls.Config{Certificates: []tls.Certificate{cer}}
		listener, err = tls.Listen("tcp", *listen, config)
		if err != nil {
			log.Fatalf("Failed to listen to %s: %s", *listen, err)
		}
	} else {
		listener, err = net.Listen("tcp", *listen)
		if err != nil {
			log.Fatalf("Failed to listen to %s: %s", *listen, err)
		}
	}

	h := handler{
		Target:       *targetProduction,
		Alternatives: arrayAlternatives(altServers),
		Randomizer:   *rand.New(rand.NewSource(time.Now().UnixNano())),
	}

	h.SetSchemes()

	server := &http.Server{
		Handler: h,
	}
	if *closeConnections {
		// Close connections to clients by setting the "Connection": "close" header in the response.
		server.SetKeepAlivesEnabled(false)
	}
	server.Serve(listener)
}

type nopCloser struct {
	io.Reader
}

func (nopCloser) Close() error { return nil }

// DuplicateRequest duplicate http request
func DuplicateRequest(request *http.Request) (dup *http.Request) {
	var bodyBytes []byte
	if request.Body != nil {
		bodyBytes, _ = ioutil.ReadAll(request.Body)
	}
	request.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))
	dup = &http.Request{
		Method:        request.Method,
		URL:           request.URL,
		Proto:         request.Proto,
		ProtoMajor:    request.ProtoMajor,
		ProtoMinor:    request.ProtoMinor,
		Header:        request.Header,
		Body:          ioutil.NopCloser(bytes.NewBuffer(bodyBytes)),
		Host:          request.Host,
		ContentLength: request.ContentLength,
		Close:         true,
	}
	return
}

func updateForwardedHeaders(request *http.Request) {
	positionOfColon := strings.LastIndex(request.RemoteAddr, ":")
	var remoteIP string
	if positionOfColon != -1 {
		remoteIP = request.RemoteAddr[:positionOfColon]
	} else {
		log.Printf("The default format of request.RemoteAddr should be IP:Port but was %s\n", remoteIP)
		remoteIP = request.RemoteAddr
	}
	insertOrExtendForwardedHeader(request, remoteIP)
	insertOrExtendXFFHeader(request, remoteIP)
}

const XFF_HEADER = "X-Forwarded-For"

func insertOrExtendXFFHeader(request *http.Request, remoteIP string) {
	header := request.Header.Get(XFF_HEADER)
	if header != "" {
		// extend
		request.Header.Set(XFF_HEADER, header+", "+remoteIP)
	} else {
		// insert
		request.Header.Set(XFF_HEADER, remoteIP)
	}
}

const FORWARDED_HEADER = "Forwarded"

// Implementation according to rfc7239
func insertOrExtendForwardedHeader(request *http.Request, remoteIP string) {
	extension := "for=" + remoteIP
	header := request.Header.Get(FORWARDED_HEADER)
	if header != "" {
		// extend
		request.Header.Set(FORWARDED_HEADER, header+", "+extension)
	} else {
		// insert
		request.Header.Set(FORWARDED_HEADER, extension)
	}
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func readConfigFile(filePath *string) {
	if fileExists(*filePath) {
		systemMap = make(map[string]string)
		log.Printf("Found config file at %s.", filePath)
		dat, err := ioutil.ReadFile(*filePath)
		check(err)
		fileData := string(dat)
		var lines = strings.Split(fileData, "\n")
		for _, line := range lines {
			fmt.Println(line)
			if !strings.HasPrefix(line, "#") {
				line = strings.TrimRight(line, "\r \n")
				var linevals = strings.Split(line, ",")
				if len(linevals) > 1 {
					if linevals[1] == "url" {
						log.Printf("adding %s %s to the systemMap", linevals[0], linevals[2])
						systemMap[linevals[0]] = linevals[2]
					}
				}
			}
		}
	} else {
		panic(errors.New("A config file was specified but could not be found!"))
	}
}
