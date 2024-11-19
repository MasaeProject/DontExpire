package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

var verbose bool

func main() {
	var domains string
	var checkSSLFlag bool
	var checkDomainFlag bool
	var useProxy bool
	var whoisServer string

	flag.StringVar(&domains, "u", "", "输入一个或多个域名（用,分隔）")
	flag.BoolVar(&checkSSLFlag, "s", false, "检查SSL证书是否过期")
	flag.BoolVar(&checkDomainFlag, "d", false, "检查域名是否过期")
	flag.BoolVar(&useProxy, "p", false, "通过代理服务器检查")
	flag.BoolVar(&verbose, "v", false, "输出详细内容")
	flag.StringVar(&whoisServer, "w", "whois.iana.org", "指定 WHOIS 服务器")
	flag.Parse()

	if verbose {
		fmt.Println("域名和证书过期时间检查程序")
	}

	if domains == "" {
		fmt.Println("请提供一个域名 -u <网站域名>")
		os.Exit(1)
	}

	domainList := strings.Split(domains, ",")

	// 如果既未提供 -s 也未提供 -d，则默认开启 -s
	if !checkSSLFlag && !checkDomainFlag {
		checkSSLFlag = true
	}

	for _, domain := range domainList {
		domain = strings.TrimSpace(domain)
		if checkSSLFlag {
			if verbose {
				fmt.Printf("开始检查 %s 的 SSL 证书...\n", domain)
			}
			checkSSL(domain)
		}

		if checkDomainFlag {
			if verbose {
				fmt.Printf("开始检查 %s 的域名到期...\n", domain)
			}
			// checkDomainExpiry(domain, whoisServer)
		}
	}
}
