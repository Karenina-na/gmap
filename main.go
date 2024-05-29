package main

import (
	"fmt"
	"gmap/src/tcp/syn"
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
	// Ping
	log, payload, err := syn.SendSynRequest(
		"192.168.80.1", 27842,
		"192.168.80.200", 80, time.Duration(1000)*time.Millisecond,
	)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(payload)
	fmt.Println(log)
}
