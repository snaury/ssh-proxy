package main

import (
	"flag"
	"fmt"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/user"
	"strings"
	"sync"
	"time"
)

func currentUser() *user.User {
	u, err := user.Current()
	if err != nil {
		panic(err)
	}
	return u
}

func defaultUsername() string {
	u := currentUser()
	name := u.Username
	index := strings.Index(name, "\\")
	if index != -1 {
		name = name[index+1:]
	}
	return name
}

func defaultKeyFile() string {
	return currentUser().HomeDir + "/.ssh/id_rsa"
}

func loadKeyFile(filename string) (key ssh.Signer, err error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return
	}
	key, err = ssh.ParsePrivateKey(data)
	if err != nil {
		return
	}
	return
}

func ensurePort(host string, defaultPort int) string {
	cindex := strings.Index(host, ":")
	if cindex == -1 {
		return fmt.Sprintf("%s:%d", host, defaultPort)
	}
	return host
}

func extractHost(url *url.URL) string {
	host := url.Host
	cindex := strings.Index(host, ":")
	if cindex != -1 {
		host = host[:cindex]
	}
	return host
}

func extractHostPort(url *url.URL, defaultPort int) string {
	hostport := url.Host
	cindex := strings.Index(hostport, ":")
	if cindex == -1 {
		hostport = fmt.Sprintf("%s:%d", hostport, defaultPort)
	}
	return hostport
}

type SecureReverseProxy struct {
	host            string
	config          *config
	sshConfig       *ssh.ClientConfig
	remoteAvailable *sync.Cond
	remote          *ssh.Client
	proxy           httputil.ReverseProxy
	direct          httputil.ReverseProxy
}

func (p *SecureReverseProxy) getActions(url *url.URL) configActions {
	host := extractHost(url)
	if p.config != nil {
		for _, c := range p.config.cases {
			if c.mask.MatchString(host) {
				return c.actions
			}
		}
	}
	return actionNone
}

func NewSecureReverseProxy(host string, config *config, sshConfig *ssh.ClientConfig) *SecureReverseProxy {
	p := &SecureReverseProxy{}
	p.host = host
	p.config = config
	p.sshConfig = sshConfig
	p.remoteAvailable = sync.NewCond(&sync.Mutex{})
	p.proxy.Director = func(req *http.Request) {}
	p.proxy.Transport = &http.Transport{
		Proxy: nil,
		Dial:  p.dial,
	}
	p.direct.Director = func(req *http.Request) {}
	go p.reconnectLoop()
	return p
}

func (p *SecureReverseProxy) reconnectLoop() {
	p.remoteAvailable.L.Lock()
	defer p.remoteAvailable.L.Unlock()
	for {
		log.Printf("Connecting to %s...", p.host)
		remote, err := ssh.Dial("tcp", p.host, p.sshConfig)
		if err != nil {
			log.Printf("Connect failed: %s", err)
			time.Sleep(5 * time.Second)
			continue
		}
		p.remote = remote
		p.remoteAvailable.Broadcast()
		p.remoteAvailable.L.Unlock()
		log.Printf("Connected to %s\n", remote.ServerVersion())
		err = remote.Wait()
		p.remoteAvailable.L.Lock()
		p.remote = nil
		if err != nil {
			log.Printf("Disconnected: %s", err)
		}
		remote.Close()
	}
}

func (p *SecureReverseProxy) dial(n, addr string) (net.Conn, error) {
	p.remoteAvailable.L.Lock()
	for p.remote == nil {
		p.remoteAvailable.Wait()
	}
	remote := p.remote
	p.remoteAvailable.L.Unlock()
	c, err := remote.Dial(n, addr)
	if err != nil {
		log.Printf("CONNECT %s: %s", addr, err)
	}
	return c, err
}

func isNormalError(err error) bool {
	if err == io.EOF {
		return true
	}
	if neterr, ok := err.(net.Error); ok && neterr.Timeout() {
		return true
	}
	return false
}

func (p *SecureReverseProxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	var url string
	var origurl string
	actions := p.getActions(req.URL)
	redirect := false
	if req.Method == "CONNECT" {
		origurl = extractHostPort(req.URL, 443)
	} else {
		origurl = req.URL.String()
		if req.URL.Scheme == "http" && actions&actionForceHTTPS != 0 {
			if req.Method == "GET" || req.Method == "HEAD" {
				redirect = true
			}
			req.URL.Scheme = "https"
			url = req.URL.String()
		}
	}
	if len(url) == 0 {
		url = origurl
	}
	prefix := ""
	if actions&actionDirect != 0 {
		prefix = "(direct) "
	}
	log.Printf("%s%s %s", prefix, req.Method, origurl)

	if actions&actionBlock != 0 {
		rw.WriteHeader(503)
		io.WriteString(rw, "Server blocked")
		return
	}

	if redirect {
		rw.Header().Set("Location", url)
		rw.WriteHeader(307)
		if req.Method == "GET" {
			io.WriteString(rw, url)
		}
		return
	}

	if req.Method == "CONNECT" {
		rwh, ok := rw.(http.Hijacker)
		if !ok {
			rw.WriteHeader(503)
			io.WriteString(rw, "Cannot hijack connection for the CONNECT method")
			return
		}

		dial := p.dial
		if actions&actionDirect != 0 {
			dial = net.Dial
		}

		remote, err := dial("tcp", url)
		if err != nil {
			rw.WriteHeader(503)
			io.WriteString(rw, "CONNECT failed: "+err.Error())
			log.Printf("%s %s: %s", req.Method, url, err)
			return
		}
		defer remote.Close()

		local, b, err := rwh.Hijack()
		if err != nil {
			rw.WriteHeader(503)
			io.WriteString(rw, "HIJACK failed: "+err.Error())
			return
		}
		defer local.Close()
		io.WriteString(b, "HTTP/1.1 200 OK\r\n\r\n")
		b.Flush() // this is the last write into b

		// write side runs it its own goroutine
		go func() {
			defer local.Close()
			defer remote.Close()
			var buffer [65536]byte
			done := false
			for !done {
				n, err := remote.Read(buffer[:])
				if n > 0 {
					_, werr := local.Write(buffer[:n])
					if werr != nil {
						if !isNormalError(werr) {
							//log.Printf("%s: local write: %s", url, werr)
						}
						done = true
					}
				}
				if err != nil {
					if !isNormalError(err) {
						//log.Printf("%s: remote read: %s", url, err)
					}
					done = true
				}
			}
		}()

		// read side runs here, first we grab what we have in in b
		var buffer [65536]byte
		done := false
		for !done {
			n, err := b.Read(buffer[:])
			if n > 0 {
				_, werr := remote.Write(buffer[:n])
				if werr != nil {
					if !isNormalError(werr) {
						//log.Printf("%s: remote write: %s", url, werr)
					}
					done = true
				}
			}
			if err != nil {
				if !isNormalError(err) {
					//log.Printf("%s: local read: %s", url, err)
				}
				done = true
			}
		}
		return
	}

	if actions&actionDirect != 0 {
		p.direct.ServeHTTP(rw, req)
	} else {
		p.proxy.ServeHTTP(rw, req)
	}
}

func (p *SecureReverseProxy) ListenAndServe(addr string) error {
	return http.ListenAndServe(addr, p)
}

func main() {
	var host string
	var keyFile string
	var configFile string = "config.txt"
	var listenAddr string = "127.0.0.1:8080"
	flag.StringVar(&host, "host", host, "ssh hostname")
	flag.StringVar(&keyFile, "key", keyFile, "ssh key file")
	flag.StringVar(&configFile, "config", configFile, "proxy config file")
	flag.StringVar(&listenAddr, "listen", listenAddr, "proxy listen address")
	flag.Parse()
	if host == "" {
		flag.Usage()
		return
	}
	host = ensurePort(host, 22)

	// Determine which auth methods we can use
	var authMethods []ssh.AuthMethod
	if authsock := os.Getenv("SSH_AUTH_SOCK"); authsock != "" {
		// Connect to local ssh agent
		var conn net.Conn
		var err error
		if authsock[0] == '/' || authsock[0] == '@' {
			conn, err = net.Dial("unix", authsock)
		} else {
			conn, err = net.Dial("tcp", authsock)
		}
		if err != nil {
			log.Fatal(err)
		}
		defer conn.Close()
		client := agent.NewClient(conn)
		authMethods = append(authMethods, ssh.PublicKeysCallback(client.Signers))
	}
	if len(authMethods) == 0 && keyFile == "" {
		// Use default key when there's no agent
		keyFile = defaultKeyFile()
	}
	if keyFile != "" {
		// Key file must not have a password
		key, err := loadKeyFile(keyFile)
		if err != nil {
			log.Fatal(err)
		}
		authMethods = append(authMethods, ssh.PublicKeys(key))
	}
	if len(authMethods) == 0 {
		log.Fatal("No authentication methods specified")
	}
	config, err := loadConfigFile(configFile)
	if err != nil {
		log.Fatal(err)
	}
	sshConfig := &ssh.ClientConfig{
		User: defaultUsername(),
		Auth: authMethods,
	}
	p := NewSecureReverseProxy(host, config, sshConfig)
	err = p.ListenAndServe(listenAddr)
	if err != nil {
		log.Fatal(err)
	}
}
