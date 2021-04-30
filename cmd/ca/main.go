/*
 *
 * Copyright (C) 2021 Markku Rossi.
 *
 * All rights reserved.
 *
 */

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/user"
	"time"
)

// Challenge implements login challenge from the PAM module.
type Challenge struct {
	Username string
	Hostname string
	Time     uint32
}

func (c Challenge) String() string {
	return fmt.Sprintf("%s %s@%s",
		time.Unix(int64(c.Time), 0).Format(time.RFC3339),
		c.Username, c.Hostname)
}

// Token implements authentication token.
type Token struct {
	FromUser string
	Username string
	Hostname string
	SignTime uint32
	HostTime uint32
}

// Certificate implements signed authentication token.
type Certificate struct {
	Token     []byte
	Signature []byte
}

func main() {
	log.SetFlags(0)
	challenge := flag.String("c", "", "Challenge")
	flag.Parse()

	if len(flag.Args()) == 0 {
		log.Printf(`Usage: ca [OPTION]... COMMAND...

Supported commands are:
  make-keys     generate CA key pair
  sign          sign certificate

Supported options are:
`)
		flag.PrintDefaults()
	}

	for _, arg := range flag.Args() {
		switch arg {
		case "make-keys":
			pub, priv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				log.Fatalf("ed25519.GenerateKey: %s", err)
			}
			if err := save(pub, "ca.pub"); err != nil {
				log.Fatalf("save failed: %s", err)
			}
			if err := save(priv, "ca.priv"); err != nil {
				log.Fatalf("save failed: %s", err)
			}

		case "sign":
			if len(*challenge) == 0 {
				log.Fatalf("no challenge")
			}
			data, err := base64.StdEncoding.DecodeString(*challenge)
			if err != nil {
				log.Fatalf("invalid challenge: %s", err)
			}
			var decoded Challenge
			err = Unmarshal(data, &decoded)
			if err != nil {
				log.Fatalf("invalid challenge: %s", err)
			}
			log.Printf("challenge: %s", decoded)

			priv, err := load("ca.priv")
			if err != nil {
				log.Fatalf("failed to load private key: %s", err)
			}

			user, err := user.Current()
			if err != nil {
				log.Fatalf("failed to get current user: %s", err)
			}

			token := Token{
				FromUser: user.Username,
				Username: decoded.Username,
				Hostname: decoded.Hostname,
				SignTime: uint32(time.Now().Unix()),
				HostTime: decoded.Time,
			}
			toSign, err := Marshal(&token)
			if err != nil {
				log.Fatalf("marshal failed: %s", err)
			}
			cert := Certificate{
				Token:     toSign,
				Signature: ed25519.Sign(priv, toSign),
			}

			encoded, err := Marshal(&cert)
			if err != nil {
				log.Fatalf("marshal failed: %s", err)
			}

			log.Printf("Certificate: %s",
				base64.StdEncoding.EncodeToString(encoded))

		default:
			log.Fatalf("unknown command: %s", arg)
		}
	}
}

func save(data []byte, file string) error {
	f, err := os.Create(file)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.Write([]byte(base64.StdEncoding.EncodeToString(data)))
	return err
}

func load(file string) ([]byte, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(string(data))
}
