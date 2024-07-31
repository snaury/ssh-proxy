package main

import (
	"errors"
	"flag"
	"fmt"
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

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
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
		err = p.connected(remote)
		if err != nil {
			log.Printf("Disconnected: %s", err)
		}
		remote.Close()
	}
}

func (p *SecureReverseProxy) connected(remote *ssh.Client) error {
	p.remote = remote
	defer func() {
		p.remote = nil
	}()

	p.remoteAvailable.Broadcast()
	p.remoteAvailable.L.Unlock()
	defer p.remoteAvailable.L.Lock()

	log.Printf("Connected to %s\n", remote.ServerVersion())
	stop := make(chan struct{})
	defer close(stop)
	go p.keepalive(remote, stop)
	return remote.Wait()
}

func (p *SecureReverseProxy) keepalive(remote *ssh.Client, stop <-chan struct{}) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			// just try to connect somewhere once in a while, error is not important
			c, err := remote.Dial("tcp", "127.255.255.42:0")
			if err == nil {
				c.Close()
			}
		}
	}
}

func (p *SecureReverseProxy) waitForRemote() *ssh.Client {
	p.remoteAvailable.L.Lock()
	defer p.remoteAvailable.L.Unlock()
	for p.remote == nil {
		p.remoteAvailable.Wait()
	}
	return p.remote
}

func (p *SecureReverseProxy) dial(n, addr string) (net.Conn, error) {
	remote := p.waitForRemote()
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

type fragmentedReader struct {
	io.Reader
	header       [5]byte
	buffer       []byte
	handshake    []byte
	handshakeErr error
	processed    bool
}

var errNotHandshakeRecord = errors.New("not a handshake record")

func (c *fragmentedReader) readHandshakeRecord() ([]byte, error) {
	n, err := io.ReadFull(c.Reader, c.header[:5])
	c.buffer = append(c.buffer, c.header[:n]...)
	if err != nil {
		if err == io.ErrUnexpectedEOF {
			err = io.EOF
		}
		return nil, err
	}
	// log.Printf("readHandshakeRecord: header %q", c.header[:5])

	// TLS 1.0 handshake record
	if c.header[0] == 0x16 && c.header[1] == 0x03 && c.header[2] == 0x01 {
		n = int(c.header[3])<<8 | int(c.header[4])
		b := make([]byte, n)
		n, err = io.ReadFull(c.Reader, b)
		c.buffer = append(c.buffer, b[:n]...)
		if err != nil {
			if err == io.ErrUnexpectedEOF {
				err = io.EOF
			}
			return nil, err
		}

		// log.Printf("readHandshakeRecord: data %q", b)
		return b, nil
	}

	// not a handshake record
	return nil, errNotHandshakeRecord
}

func (c *fragmentedReader) readHandshakeBytes(n int) error {
	for len(c.handshake) < n {
		b, err := c.readHandshakeRecord()
		if err != nil {
			return err
		}
		c.handshake = append(c.handshake, b...)
	}
	return nil
}

func (c *fragmentedReader) appendHandshakeRecord(b []byte) {
	for len(b) > 0 {
		n := len(b)
		if n > 65535 {
			n = 65535
		}
		c.buffer = append(c.buffer, 0x16, 0x03, 0x01, byte(n>>8), byte(n))
		c.buffer = append(c.buffer, b[:n]...)
		b = b[n:]
	}
}

func findSnameExt(b []byte) (int, int) {
	pos := 0
	for len(b) >= 4 {
		n := int(b[2])<<8 | int(b[3])
		if !(4+n <= len(b)) {
			break
		}
		if b[0] == 0 && b[1] == 0 {
			return pos + 4, n
		}
		b = b[4+n:]
		pos += 4 + n
	}
	return -1, -1
}

func (c *fragmentedReader) processClientHello() error {
	err := c.readHandshakeBytes(4)
	if err != nil {
		log.Printf("failed to read 4 bytes (client hello header): %s", err)
		if err == errNotHandshakeRecord {
			err = nil
		}
		return err
	}
	if c.handshake[0] != 0x01 {
		// expected client hello message
		return nil
	}
	n := int(c.handshake[1])<<16 | int(c.handshake[2])<<8 | int(c.handshake[3])
	err = c.readHandshakeBytes(4 + n)
	if err != nil {
		log.Printf("failed to read %d bytes (client hello data): %s", n, err)
		if err == errNotHandshakeRecord {
			err = nil
		}
		return err
	}
	pos := 4
	end := 4 + n
	if !(pos+2 <= end) || c.handshake[pos] != 0x03 || c.handshake[pos+1] != 0x03 {
		// expected TLS 1.2 outer layer
		return nil
	}
	pos += 2 + 32
	// skip session id
	if !(pos+1 <= end) {
		return nil
	}
	k := int(c.handshake[pos])
	pos += 1 + k
	// skip cipher suites
	if !(pos+2 <= end) {
		return nil
	}
	k = int(c.handshake[pos])<<8 | int(c.handshake[pos+1])
	pos += 2 + k
	// skip compression methods
	if !(pos+1 <= end) {
		return nil
	}
	k = int(c.handshake[pos])
	pos += 1 + k
	// extensions
	if !(pos+2 <= end) {
		return nil
	}
	extSize := int(c.handshake[pos])<<8 | int(c.handshake[pos+1])
	if extSize < 4 {
		return nil
	}
	pos += 2
	extStart := pos
	extEnd := extStart + extSize
	if !(extEnd <= end) {
		return nil
	}
	ext := c.handshake[extStart:extEnd]

	// log.Printf("Full handshake: %x", c.handshake)
	// log.Printf("Found extensions: %q", ext)

	snameStart, snameSize := findSnameExt(ext)
	if snameStart >= 0 {
		// we found a server name extension
		// let's repackage it into small fragmented records
		snameStart += extStart
		snameEnd := snameStart + snameSize
		log.Printf("Fragmenting sname: %q", c.handshake[snameStart:snameEnd])
		pos = snameStart - 3 // we want to fragment the 00 00 tag as well
		// log.Printf("Original buffer: %q", c.buffer)
		c.buffer = c.buffer[:0]
		c.appendHandshakeRecord(c.handshake[:pos])
		for pos+2 < snameEnd {
			c.appendHandshakeRecord(c.handshake[pos : pos+2])
			pos += 2
		}
		c.appendHandshakeRecord(c.handshake[pos:])
		// log.Printf("Final buffer: %q", c.buffer)
	}

	return nil
}

func (c *fragmentedReader) Read(b []byte) (int, error) {
	if !c.processed {
		err := c.processClientHello()
		if err != nil {
			c.handshakeErr = err
		}
		c.processed = true
	}
	if len(c.buffer) > 0 {
		n := len(c.buffer)
		if n > len(b) {
			n = len(b)
		}
		copy(b[:n], c.buffer[:n])
		c.buffer = c.buffer[n:]
		if len(c.buffer) == 0 {
			c.buffer = nil
		}
		return n, nil
	}
	if c.handshakeErr != nil {
		return 0, c.handshakeErr
	}
	n, err := c.Reader.Read(b)
	return n, err
}

func (p *SecureReverseProxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if req.Host == "localhost" || strings.HasPrefix(req.Host, "localhost:") {
		rw.WriteHeader(200)
		io.WriteString(rw, "TODO: console")
		return
	}
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
	if actions&actionFragment != 0 {
		prefix += "(fragmented) "
	}
	suffix := ""
	if actions&actionBlock != 0 {
		suffix = " (blocked)"
	}
	log.Printf("%s%s %s%s", prefix, req.Method, origurl, suffix)

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

		// write side runs in its own goroutine
		go func() {
			defer local.Close()
			defer remote.Close()
			var buffer [1024]byte
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

		var r io.Reader = b
		if actions&actionFragment != 0 {
			r = &fragmentedReader{
				Reader: r,
			}
		}

		// read side runs here, first we grab what we have in in b
		var buffer [1024]byte
		done := false
		for !done {
			n, err := r.Read(buffer[:])
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
		User:            defaultUsername(),
		Auth:            authMethods,
		Timeout:         30 * time.Second,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	p := NewSecureReverseProxy(host, config, sshConfig)
	err = p.ListenAndServe(listenAddr)
	if err != nil {
		log.Fatal(err)
	}
}
