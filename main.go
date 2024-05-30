package main

import (
	"flag"
	"fmt"
	"gmap/src/icmp"
	"gmap/src/tcp"
	"gmap/src/util"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

/*
~ Licensed to the Apache Software Foundation (ASF) under one or more
~ contributor license agreements.  See the NOTICE file distributed with
~ this work for additional information regarding copyright ownership.
~ The ASF licenses this file to You under the Apache License, Version 2.0
~ (the "License"); you may not use this file except in compliance with
~ the License.  You may obtain a copy of the License at
~
~     http://www.apache.org/licenses/LICENSE-2.0
~
~ Unless required by applicable law or agreed to in writing, software
~ distributed under the License is distributed on an "AS IS" BASIS,
~ WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
~ See the License for the specific language governing permissions and
~ limitations under the License.
*/

// @title          gmap
// @version        1.0
// @description    A simple port scanning demo by Go.
// @termsOfService https://www.weizixiang.top
// @contact.name   Karenina-na
// @contact.url    https://www.weizixiang.top
// @contact.email  weizixiang0@outlook.com
// @license.name   Apache 2.0
// @license.url    http://www.apache.org/licenses/LICENSE-2.0.html
//
// main
// @Description:   主函数
func main() {
	ip, ports, mode, timeout := parseArg()
	var portL []string
	if *mode == "ping" {
		portL = []string{"None"}
	} else {
		portL = ports
	}
	util.Loglevel(util.Info, "gmap-main",
		fmt.Sprintf("%s | Create Scanner | IP: %s | Ports: %s | Mode: %s | Timeout: %d |",
			time.Now().Format("2006-01-02 15:04:05"),
			*ip, strings.Join(portL, ","), *mode, *timeout))

	// logs
	logs := util.NewLinkList[string](func(a, b string) bool {
		return a == b
	})
	payloads := util.NewLinkList[string](func(a, b string) bool {
		return a == b
	})
	util.Loglevel(util.Info, "gmap-main", "Start scanning...")
	if *mode == "ping" {
		if ports[0] != "A" {
			// 192.168.80.1-100
			ips := strings.Split(*ip, "-")
			IPPrefixL := strings.Split(ips[0], ".")
			IPPrefix := strings.Join(IPPrefixL[:3], ".")
			start, err1 := strconv.Atoi(strings.Split(ips[0], ".")[3])
			if err1 != nil {
				util.Loglevel(util.Error, "gmap-main", fmt.Sprintf("Error-IP: %s | %s", *ip, err1.Error()))
				os.Exit(1)
			}
			end, err2 := strconv.Atoi(ips[1])
			if err2 != nil {
				util.Loglevel(util.Error, "gmap-main", fmt.Sprintf("Error-IP: %s | %s", *ip, err2.Error()))
				os.Exit(1)
			}

			// start
			for i := start; i <= end; i++ {
				ip := IPPrefix + "." + strconv.Itoa(i)
				log, payload, err := icmp.SendPingRequest(ip, time.Duration(*timeout)*time.Millisecond)
				if err != nil {
					util.Loglevel(util.Error, "gmap-main", fmt.Sprintf("Error: %s |  %s", ip, err.Error()))
				}
				logs.Append(log)
				payloads.Append(payload)
			}

		} else {
			// 192.168.80.0/24 CIDR
			_, ipnet, err := net.ParseCIDR(*ip)
			if err != nil {
				util.Loglevel(util.Error, "gmap-main", fmt.Sprintf("Error-IP: %s | %s", *ip, err.Error()))
				os.Exit(1)
			}
			firstIP := ipnet.IP
			lastIP := make([]byte, len(firstIP))
			copy(lastIP, firstIP)
			for i := range lastIP {
				lastIP[i] |= ^ipnet.Mask[i]
			}
			for ip := ipnet.IP.Mask(ipnet.Mask); !ip.Equal(lastIP); util.CIDRIncrementIP(ip) {
				log, payload, err := icmp.SendPingRequest(ip.String(), time.Duration(*timeout)*time.Millisecond)
				if err != nil {
					util.Loglevel(util.Error, "gmap-main", fmt.Sprintf("Error: %s | %s", ip.String(), err.Error()))
				}
				logs.Append(log)
				payloads.Append(payload)
			}
		}

	} else { // other like tcp
		for p := range ports {
			switch *mode {
			case "tcp": // tcp
				log, payload, err := tcp.SendTCPRequest(*ip, ports[p], time.Duration(*timeout)*time.Millisecond)
				if err != nil {
					util.Loglevel(util.Error, "gmap-main", fmt.Sprintf("Error-IP: %s | Port: %s | %s", *ip, ports[p], err.Error()))
				}
				logs.Append(log)
				payloads.Append(payload)
				break
			}
		}
	}
	util.Loglevel(util.Info, "gmap-main", "Scan completed.")
}

// IpReg IpReg
const IpReg = "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"

// NtReg NtReg
const NtReg = "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])/([1-9]|[1-2][0-9]|3[0-2])$"

// LocalhostReg LocalhostReg
const LocalhostReg = "^(localhost|127\\.0\\.0\\.1)$"

// PortReg PortReg
const PortReg = "^([0-9]|[1-9]\\d|[1-9]\\d{2}|[1-9]\\d{3}|[1-5]\\d{4}|6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])$"

// PositiveReg PositiveReg
const PositiveReg = "^[1-9]\\d*$"

// parseArg
//
//	@Description: parse the command line arguments
func parseArg() (*string, []string, *string, *int) {
	// parse
	arg := flag.String("mode", "debug", "debug / release / test")
	ip := flag.String("ip", "0.0.0.0", "IP address")
	portsR := flag.String("p", "0", "Port range or single port")
	mode := flag.String("m", "tcp", "tcp / ping")
	timeout := flag.Int("t", 5, "Timeout (ms)")
	flag.Parse()

	// mode
	if *arg == "debug" {
		util.LoggerInit(func(r any) {
			fmt.Println(r)
		}, util.Debug)
	} else {
		util.LoggerInit(func(r any) {
			fmt.Println(r)
		}, util.Info)
	}
	util.Loglevel(util.Debug, "gmap-main", "Init logger success.")

	// check mode
	if *mode != "tcp" && *mode != "ping" {
		util.Loglevel(util.Error, "gmap-main", "Invalid Scan mode.")
		// exit
		os.Exit(1)
	}

	// network or ip
	var ports []string
	if *mode == "tcp" {
		// check IP
		IPCheck, _ := regexp.Match(IpReg, []byte(*ip))
		if !IPCheck {
			util.Loglevel(util.Error, "gmap-main", "Invalid IP address.")
			// exit
			os.Exit(1)
		}

		// if the port range is 80-100, then the ports will be [80, 81, 82, ..., 100]
		portsT := strings.Split(*portsR, "-")
		if len(portsT) == 2 {
			first, err1 := strconv.Atoi(portsT[0])
			if err1 != nil {
				util.Loglevel(util.Error, "gmap-main", "Invalid port.")
				os.Exit(1)
			}
			second, err2 := strconv.Atoi(portsT[1])
			if err2 != nil {
				util.Loglevel(util.Error, "gmap-main", "Invalid port.")
				os.Exit(1)
			}
			for i := first; i <= second; i++ {
				ports = append(ports, strconv.Itoa(i))
			}
		} else {
			// if the port range is 80, then the ports will be [80]
			portsT = strings.Split(*portsR, ",")
			if len(portsT) == 1 {
				ports = append(ports, portsT[0])
			} else {
				ports = append(ports, portsT...)
			}
			for i, port := range ports {
				ports[i] = strings.TrimSpace(port)
			}
			// check port
			for _, port := range ports {
				PortCheck, _ := regexp.Match(PortReg, []byte(port))
				if !PortCheck {
					util.Loglevel(util.Error, "gmap-main", "Invalid port.")
					// exit
					os.Exit(1)
				}
			}
		}
	} else { // ping
		// 192.168.80.1-100
		if strings.Contains(*ip, "-") {
			ips := strings.Split(*ip, "-")
			if len(ips) != 2 {
				util.Loglevel(util.Error, "gmap-main", "Invalid network segment.")
				// exit
				os.Exit(1)
			}
			// check IP
			IPCheck, _ := regexp.Match(IpReg, []byte(ips[0]))
			if !IPCheck {
				util.Loglevel(util.Error, "gmap-main", "Invalid IP address.")
				// exit
				os.Exit(1)
			}
			// check ips2
			ips2, err := strconv.Atoi(ips[1])
			if err != nil {
				util.Loglevel(util.Error, "gmap-main", "Invalid network segment.")
				// exit
				os.Exit(1)
			}
			if ips2 <= 0 || ips2 >= 255 {
				util.Loglevel(util.Error, "gmap-main", "Invalid network segment.")
				// exit
				os.Exit(1)
			}
			ports = []string{ips[1]}
		} else {
			// check NT
			NTCheck, _ := regexp.Match(NtReg, []byte(*ip))
			if !NTCheck {
				util.Loglevel(util.Error, "gmap-main", "Invalid network segment.")
				// exit
				os.Exit(1)
			}
			ports = []string{"A"}
		}
	}

	// check timeout
	if *timeout <= 0 {
		util.Loglevel(util.Error, "gmap-main", "Invalid timeout.")
		// exit
		os.Exit(1)
	}

	return ip, ports, mode, timeout
}
