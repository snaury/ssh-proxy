package main

import (
	"fmt"
	"golang.org/x/crypto/ssh"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"os/user"
	"strings"
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

type SecureReverseProxy struct {
	remote *ssh.Client
	proxy  httputil.ReverseProxy
}

func NewSecureReverseProxy(remote *ssh.Client) *SecureReverseProxy {
	p := &SecureReverseProxy{}
	p.remote = remote
	p.proxy.Director = func(req *http.Request) {}
	p.proxy.Transport = &http.Transport{
		Proxy: nil,
		Dial: func(n, addr string) (net.Conn, error) {
			return p.remote.Dial(n, addr)
		},
	}
	return p
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
	if req.Method == "CONNECT" {
		hostport := req.URL.Host
		cindex := strings.Index(hostport, ":")
		if cindex == -1 {
			hostport += ":443"
		}
		log.Printf("%s %s", req.Method, hostport)

		rwh, ok := rw.(http.Hijacker)
		if !ok {
			rw.WriteHeader(503)
			io.WriteString(rw, "Cannot hijack connection for the CONNECT method")
			return
		}

		remote, err := p.remote.Dial("tcp", hostport)
		if err != nil {
			rw.WriteHeader(503)
			io.WriteString(rw, "CONNECT failed: "+err.Error())
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
							//log.Printf("%s: local write: %s", hostport, werr)
						}
						done = true
					}
				}
				if err != nil {
					if !isNormalError(err) {
						//log.Printf("%s: remote read: %s", hostport, err)
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
						//log.Printf("%s: remote write: %s", hostport, werr)
					}
					done = true
				}
			}
			if err != nil {
				if !isNormalError(err) {
					//log.Printf("%s: local read: %s", hostport, err)
				}
				done = true
			}
		}
		return
	}

	log.Printf("%s %s", req.Method, req.URL)
	p.proxy.ServeHTTP(rw, req)
}

func (p *SecureReverseProxy) ListenAndServe(addr string) error {
	return http.ListenAndServe(addr, p)
}

func main() {
	key, err := loadKeyFile(defaultKeyFile())
	if err != nil {
		panic(err)
	}
	config := &ssh.ClientConfig{
		User: defaultUsername(),
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(key),
		},
	}
	client, err := ssh.Dial("tcp", os.Args[1], config)
	if err != nil {
		panic(err)
	}
	defer client.Close()
	fmt.Printf("Client version: %s\n", client.ClientVersion())
	fmt.Printf("Server version: %s\n", client.ServerVersion())
	p := NewSecureReverseProxy(client)
	err = p.ListenAndServe(":8080")
	if err != nil {
		panic(err)
	}
}
