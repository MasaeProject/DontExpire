package main

import (
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"

	"golang.org/x/net/proxy"
)

var verbose bool
var proxyAddr string

func main() {
	var domains string
	var checkSSLFlag bool
	var checkDomainFlag bool
	var whoisServer string

	flag.StringVar(&domains, "u", "", "输入一个或多个域名（用,分隔）")
	flag.BoolVar(&checkSSLFlag, "s", false, "检查SSL证书是否过期")
	flag.BoolVar(&checkDomainFlag, "d", false, "检查域名是否过期")
	flag.StringVar(&proxyAddr, "p", "", "通过代理服务器，例如 socks5://127.0.0.1:1080")
	flag.BoolVar(&verbose, "v", false, "输出详细内容")
	flag.StringVar(&whoisServer, "w", "whois.iana.org", "指定 WHOIS 服务器")
	flag.Parse()

	if verbose {
		fmt.Println("域名和证书过期时间检查程序")
	}

	if domains == "" {
		fmt.Println("请提供一个或多个域名 -u <网站域名1,网站域名2,...>")
		os.Exit(1)
	}

	domainList := strings.Split(domains, ",")

	// 如果既未提供 -s 也未提供 -d，则默认开启 -s
	if !checkSSLFlag && !checkDomainFlag {
		checkSSLFlag = true
	}

	dialer, err := parseProxy(proxyAddr)
	if err != nil {
		fmt.Println("无法解析代理地址:", err)
		os.Exit(1)
	}

	for _, domain := range domainList {
		domain = strings.TrimSpace(domain)
		if checkSSLFlag {
			if verbose {
				fmt.Printf("开始检查 %s 的 SSL 证书...\n", domain)
			}
			checkSSL(domain, dialer)
		}

		if checkDomainFlag {
			if verbose {
				fmt.Printf("开始检查 %s 的域名到期...\n", domain)
			}
			checkDomainExpiry(domain, whoisServer)
		}
	}
}

func parseProxy(proxyAddr string) (proxy.Dialer, error) {
	if proxyAddr == "" {
		return proxy.Direct, nil
	}
	proxyURL, err := url.Parse(proxyAddr)
	if err != nil {
		return nil, err
	}
	return proxy.FromURL(proxyURL, proxy.Direct)
}
