package parse

import (
	"flag"
	"fmt"
	"gmap/src/util"
	"os"
	"regexp"
	"strconv"
	"strings"
)

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

// ParseArg
//
//	@Description: Parse the command line arguments
//	@return *string
//	@return []string
//	@return *string
//	@return *int
func ParseArg() (*string, []string, *string, *int, *int, *int, *int) {
	// parse
	arg := flag.String("mode", "debug", "debug / release / test")
	ip := flag.String("ip", "0.0.0.0", "IP address")
	portsR := flag.String("p", "0", "Port range or single port")
	mode := flag.String("m", "tcp", "tcp / ping")
	timeout := flag.Int("t", 5, "Timeout (ms)")
	coreThread := flag.Int("tc", 10, "Core thread number")
	maxThread := flag.Int("tm", 100, "Max thread number")
	timeoutThread := flag.Int("tt", 10000, "Timeout thread number")
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

	// check coreThread
	if *coreThread <= 0 {
		util.Loglevel(util.Error, "gmap-main", "Invalid core thread number.")
		// exit
		os.Exit(1)
	}

	// check maxThread
	if *maxThread <= 0 {
		util.Loglevel(util.Error, "gmap-main", "Invalid max thread number.")
		// exit
		os.Exit(1)
	}

	// check timeoutThread
	if *timeoutThread <= 0 {
		util.Loglevel(util.Error, "gmap-main", "Invalid timeout thread number.")
		// exit
		os.Exit(1)
	}

	return ip, ports, mode, timeout, coreThread, maxThread, timeoutThread
}
