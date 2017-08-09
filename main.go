package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"text/template"
	"time"
)

var (
	Host    = flag.String("host", "", "host[:port] to check certificate")
	Timeout = flag.Duration("timeout", time.Second, "Max time of work")
	Format  = flag.String("format", "EOL: {{.EOL_DATETIME}}", "Output format. Available fields: EOL_DATETIME, EOL_UNIXTIME, EOL_TTL")
	NoLog   = flag.Bool("nolog", false, "Disable log to stderr")
)

func main() {
	flag.Usage = usage
	flag.Parse()

	if *NoLog {
		log.SetOutput(ioutil.Discard)
	}

	ctx, ctxCancel := context.WithTimeout(context.Background(), *Timeout)
	defer ctxCancel()

	tmpl, err := template.New("template").Parse(*Format)
	if err != nil {
		log.Fatalf("Can't parse template '%s': %s", *Format, err)
	}

	host, port, err := net.SplitHostPort(*Host)
	if err != nil {
		var err2 error
		host, port, err2 = net.SplitHostPort(*Host + ":443")
		if err2 != nil {
			log.Fatalf("Can't split to host/port '%s': %s", *Host, err)
		}
	}

	hostPort := host + ":" + port
	log.Println("Host:", hostPort)
	tcpConn, err := net.DialTimeout("tcp", hostPort, *Timeout)
	if tcpConn != nil {
		defer tcpConn.Close()
	}
	if err != nil {
		log.Fatalf("Can't connect to '%s': %s", hostPort, err)
	}
	deadline, _ := ctx.Deadline()
	tcpConn.SetDeadline(deadline)

	tlsConn := tls.Client(tcpConn, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
	})
	err = tlsConn.Handshake()
	if err != nil {
		log.Fatalf("Can't handshake '%s': %s", hostPort, err)
	}

	certificates := tlsConn.ConnectionState().PeerCertificates
	if len(certificates) == 0 {
		log.Fatalf("No peer certificate after handshake '%s'", hostPort)
	}

	cert := certificates[0]

	type RESULT struct {
		EOL_DATETIME time.Time
		EOL_UNIXTIME int64
		EOL_TTL      int64
	}
	res := RESULT{
		EOL_DATETIME: cert.NotAfter.Local(),
		EOL_UNIXTIME: cert.NotAfter.Unix(),
		EOL_TTL:      cert.NotAfter.Unix() - time.Now().Unix(),
	}

	tmpl.Execute(os.Stdout, res)
}

func usage() {
	flag.CommandLine.SetOutput(os.Stdout)
	fmt.Println("https://github.com/rekby/ssl-checker2")
	flag.CommandLine.PrintDefaults()
}
