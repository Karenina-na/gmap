package main

import (
	"fmt"
	"gmap/src/icmp"
	"gmap/src/parse"
	"gmap/src/tcp"
	"gmap/src/util"
	"net"
	"os"
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
	ip, ports, mode, timeout, coreThread, maxThread, timeoutThread, savePath := parse.ParseArg()
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

	// start
	logs := util.NewLinkList[string](func(a, b string) bool {
		return a == b
	})
	payloads := util.NewLinkList[string](func(a, b string) bool {
		return a == b
	})

	// create thread pool
	RoutinePool := util.CreatePool(*coreThread, *maxThread, *timeoutThread)
	RoutinePool.SetExceptionFunc(func(r any) {
		util.Loglevel(util.Error, "go-pool", fmt.Sprintf("Error: %s", r))
	})

	// start
	util.Loglevel(util.Info, "gmap-main", "Start scanning...")
	if *mode == "ping" {
		ping(ports, ip, timeout, logs, payloads, RoutinePool)
	} else { // other like tcp
		other(ports, mode, ip, timeout, logs, payloads, RoutinePool)
	}

	// check if jobNum is 0
	for {
		_, _, _, jobNum := RoutinePool.CheckStatus()
		if jobNum == 0 {
			break
		}
		time.Sleep(time.Second)
	}

	util.Loglevel(util.Info, "gmap-main", "Scan completed.")
	// save result
	util.Loglevel(util.Info, "gmap-main", "Save result...")
	// 创建文件，并写入
	file, err := os.Create(*savePath)
	if err != nil {
		util.Loglevel(util.Error, "gmap-main", fmt.Sprintf("Error: %s", err.Error()))
		os.Exit(1)
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			util.Loglevel(util.Error, "gmap-main", fmt.Sprintf("Error: %s", err.Error()))
			os.Exit(1)
		}
	}(file)
	logs.Iterator(func(i int, log string) {
		_, _ = file.WriteString(log + " | payload: " + payloads.Get(i) + "\n")
	})
	util.Loglevel(util.Info, "gmap-main", "Save success.")
	RoutinePool.Close()
}

// ping
//
//	@Description: ping for ICMP
//	@param ports
//	@param ip
//	@param timeout
//	@param logs
//	@param payloads
func ping(ports []string, ip *string, timeout *int, logs *util.LinkList[string], payloads *util.LinkList[string], RoutinePool *util.Pool) {
	if ports[0] != "A" { // like 192.168.80.1-100
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
			fmt.Println(ip)
			RoutinePool.CreateWork(func() (E error) {
				log, payload, err := icmp.SendPingRequest(ip, time.Duration(*timeout)*time.Millisecond)
				if err != nil {
					util.Loglevel(util.Error, "gmap-main", fmt.Sprintf("Error: %s |  %s", ip, err.Error()))
				} else {
					util.Loglevel(util.Info, "gmap-main", fmt.Sprintf(log))
					logs.Append(log)
					payloads.Append(payload)
				}
				return nil
			}, func(Message error) {
				util.Loglevel(util.Error, "gmap-main", fmt.Sprintf("Error: %s", Message))
			})
		}

	} else { // like 192.168.80.0/24 CIDR
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

		// start
		for ip := ipnet.IP.Mask(ipnet.Mask); !ip.Equal(lastIP); util.CIDRIncrementIP(ip) {
			//log, payload, err := icmp.SendPingRequest(ip.String(), time.Duration(*timeout)*time.Millisecond)
			//if err != nil {
			//	util.Loglevel(util.Error, "gmap-main", fmt.Sprintf("Error: %s | %s", ip.String(), err.Error()))
			//} else {
			//	util.Loglevel(util.Info, "gmap-main", fmt.Sprintf(log))
			//	logs.Append(log)
			//	payloads.Append(payload)
			//}
			ips := ip.String()
			RoutinePool.CreateWork(func() (E error) {
				log, payload, err := icmp.SendPingRequest(ips, time.Duration(*timeout)*time.Millisecond)
				if err != nil {
					util.Loglevel(util.Error, "gmap-main", fmt.Sprintf("Error: %s | %s", ips, err.Error()))
				} else {
					util.Loglevel(util.Info, "gmap-main", fmt.Sprintf(log))
					logs.Append(log)
					payloads.Append(payload)
				}
				return nil
			}, func(Message error) {
				util.Loglevel(util.Error, "gmap-main", fmt.Sprintf("Error: %s", Message))
			})
		}
	}
}

// other
//
//	@Description:  other except ping
//	@param ports
//	@param mode
//	@param ip
//	@param timeout
//	@param logs
//	@param payloads
func other(ports []string, mode *string, ip *string, timeout *int, logs *util.LinkList[string], payloads *util.LinkList[string], RoutinePool *util.Pool) {
	for p := range ports {
		switch *mode {
		case "tcp": // tcp
			//log, payload, err := tcp.SendTCPRequest(*ip, ports[p], time.Duration(*timeout)*time.Millisecond)
			//if err != nil {
			//	util.Loglevel(util.Error, "gmap-main", fmt.Sprintf("Error-IP: %s | Port: %s | %s", *ip, ports[p], err.Error()))
			//} else {
			//	util.Loglevel(util.Info, "gmap-main", fmt.Sprintf(log))
			//	logs.Append(log)
			//	payloads.Append(payload)
			//}
			ips := *ip
			portT := ports[p]
			RoutinePool.CreateWork(func() (E error) {
				log, payload, err := tcp.SendTCPRequest(*ip, portT, time.Duration(*timeout)*time.Millisecond)
				if err != nil {
					util.Loglevel(util.Error, "gmap-main", fmt.Sprintf("Error-IP: %s | Port: %s | %s", ips, portT, err.Error()))
				} else {
					util.Loglevel(util.Info, "gmap-main", fmt.Sprintf(log))
					logs.Append(log)
					payloads.Append(payload)
				}
				return nil
			}, func(Message error) {
				util.Loglevel(util.Error, "gmap-main", fmt.Sprintf("Error: %s", Message))
			})
			break
		}
	}
}
