package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"text/template"
	"time"
)

var (
	Host        = flag.String("host", "", "host[:port] to check certificate")
	OutEOL      = flag.Bool("out-eol", false, "Print unix time stamp of eol certificate (norman time in human mode")
	HumanFormat = flag.Bool("human", false, "Display result in human readable format. Bad for parsing.")
	Timeout     = flag.Duration("timeout", time.Second, "Max time of work")
	NoTitle     = flag.Bool("notitle", false, "No out line header")
	Format      = flag.String("format", "EOL: {{.EOL_DATETIME}}", "Output format. Available fields: EOL_DATETIME, EOL_UNIXTIME")
)

type RESULT struct {
	EOL_DATETIME time.Time
	EOL_UNIXTIME int64
}

func main() {
	flag.Usage = usage
	flag.Parse()

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
	})
	err = tlsConn.Handshake()
	if err != nil {
		log.Fatal("Can't handshake '%s': %s", hostPort, err)
	}

	certificates := tlsConn.ConnectionState().PeerCertificates
	if len(certificates) == 0 {
		log.Fatal("No peer certificate after handshake '%s'", hostPort)
	}

	cert := certificates[0]

	res := RESULT{
		EOL_DATETIME: cert.NotAfter,
		EOL_UNIXTIME: cert.NotAfter.Unix(),
	}

	tmpl.Execute(os.Stdout, res)
}

func usage() {
	flag.CommandLine.SetOutput(os.Stdout)
	fmt.Println("https://github.com/rekby/ssl-checker2")
	flag.CommandLine.PrintDefaults()
}
