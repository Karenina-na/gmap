package main

import (
	"flag"
	"fmt"
	"gmap/src/util"
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
	util.Loglevel(util.Info, "gmap-main",
		fmt.Sprintf("%s | Create Scanner | IP: %s | Ports: %s | Mode: %s | Timeout: %d |",
			time.Now().Format("2006-01-02 15:04:05"),
			*ip, strings.Join(ports, ","), *mode, *timeout))
	util.Loglevel(util.Info, "gmap-main", "Start scanning...")
}

// IpReg IpReg
const IpReg = "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"

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

	// check IP
	IPCheck, _ := regexp.Match(IpReg, []byte(*ip))
	if !IPCheck {
		util.Loglevel(util.Error, "gmap-main", "Invalid IP address.")
		// exit
		os.Exit(1)
	}

	var ports []string
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

	// check mode
	if *mode != "tcp" && *mode != "ping" {
		util.Loglevel(util.Error, "gmap-main", "Invalid Scan mode.")
		// exit
		os.Exit(1)
	}

	// check timeout
	if *timeout <= 0 {
		util.Loglevel(util.Error, "gmap-main", "Invalid timeout.")
		// exit
		os.Exit(1)
	}

	return ip, ports, mode, timeout
}
