package main

import (
	"fmt"
	"net"
	"regexp"
	"time"
)

func checkDomainExpiry(domain string, whoisServer string) {
	conn, err := net.Dial("tcp", whoisServer+":43")
	if err != nil {
		fmt.Printf("无法连接到 WHOIS 服务器 %s : %v\n", domain, err)
		return
	}
	defer conn.Close()

	fmt.Fprintf(conn, "%s\r\n", domain)
	resp := make([]byte, 1024)
	n, err := conn.Read(resp)
	if err != nil {
		fmt.Printf("读取 WHOIS 服务器响应失败 (%s): %v\n", domain, err)
		return
	}

	response := string(resp[:n])
	if verbose {
		fmt.Printf("%s 的 WHOIS 服务器 %s(%s) 响应:\n", domain, whoisServer, conn.RemoteAddr())
		fmt.Println(response)
	}

	r := regexp.MustCompile(`(?i)(Expiration Date|Registry Expiry Date|expires on|Renewal date):\s*(\d{4}-\d{2}-\d{2})`)
	matches := r.FindStringSubmatch(response)
	if len(matches) > 2 {
		expiryDate, err := time.Parse("2006-01-02", matches[2])
		if err == nil {
			daysLeft := int(time.Until(expiryDate).Hours() / 24)
			fmt.Printf("%s 域名到期日期: %s\n", domain, expiryDate.Format("2006-01-02"))
			fmt.Printf("%s 距离到期还有: %d 天\n", domain, daysLeft)
		} else {
			fmt.Printf("%s : 无法解析到期时间\n", domain)
		}
	} else {
		fmt.Printf("%s : 未能找到到期时间\n", domain)
	}
}
