package main

import (
	"crypto/tls"
	"fmt"
	"strings"
	"time"
)

func checkSSL(domain string) {
	conn, err := tls.Dial("tcp", domain+":443", &tls.Config{})
	if err != nil {
		fmt.Printf("SSL 连接失败 (%s): %v\n", domain, err)
		if strings.Contains(err.Error(), "certificate has expired") || strings.Contains(err.Error(), "not yet valid") {
			config := &tls.Config{InsecureSkipVerify: true}
			conn, err = tls.Dial("tcp", domain+":443", config)
			if err != nil {
				if verbose {
					fmt.Printf("无法获取证书信息 (%s): %v\n", domain, err)
				}
				return
			}
		}
	}
	defer conn.Close()

	cert := conn.ConnectionState().PeerCertificates[0]
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
		fmt.Printf("%s :\n", domain)
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
