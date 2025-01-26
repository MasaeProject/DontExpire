package main

// go run . -u google.com -p socks5://127.0.0.1:23332 -s -v

import (
	"crypto/tls"
	"fmt"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

func checkSSL(domain string, dialer proxy.Dialer) {
	conn, err := dialer.Dial("tcp", domain+":443")
	if err != nil {
		fmt.Printf("SSL 连接失败 (%s): %v\n", domain, err)
		if strings.Contains(err.Error(), "certificate has expired") || strings.Contains(err.Error(), "not yet valid") {
			fmt.Printf("尝试获取过期的证书信息...\n")
			conn, err = dialer.Dial("tcp", domain+":443")
			if err != nil {
				fmt.Printf("无法获取证书信息 (%s): %v\n", domain, err)
				return
			}
		}
	}
	defer conn.Close()

	config := &tls.Config{ServerName: domain, InsecureSkipVerify: true}
	tlsConn := tls.Client(conn, config)
	err = tlsConn.Handshake()
	if err != nil {
		fmt.Printf("TLS 握手失败 (%s): %v\n", domain, err)
		return
	}

	cert := tlsConn.ConnectionState().PeerCertificates[0]
	notBefore := cert.NotBefore
	notAfter := cert.NotAfter
	daysLeft := int(time.Until(notAfter).Hours() / 24)
	days := ""

	if daysLeft < 0 {
		days = fmt.Sprintf("证书已过期!!: %d 天", -daysLeft)
	} else {
		days = fmt.Sprintf("证书过期还有: %d 天", daysLeft)
	}

	if verbose {
		fmt.Printf("%s ( %s ):\n", domain, conn.RemoteAddr())
		fmt.Printf("    %s\n", days)
		fmt.Printf("    证书生效日期: %s\n", notBefore.Format("2006-01-02 15:04:05"))
		fmt.Printf("    证书失效日期: %s\n", notAfter.Format("2006-01-02 15:04:05"))
		fmt.Printf("    证书颁发者: %s\n", cert.Issuer)
		fmt.Printf("    证书主题: %s\n", cert.Subject)
		fmt.Printf("    证书序列号: %s\n", cert.SerialNumber)
		fmt.Printf("    证书版本: %d\n", cert.Version)
		fmt.Printf("    证书公钥算法: %s\n", cert.PublicKeyAlgorithm)
		fmt.Printf("    证书签名算法: %s\n", cert.SignatureAlgorithm)
	} else {
		fmt.Printf("%s %s ( %s ~ %s )\n", domain, days, notBefore.Format("2006-01-02"), notAfter.Format("2006-01-02"))
	}
}
