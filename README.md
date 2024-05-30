<div align="center" style="text-align: center;">
  <h1>🤖 gmap</h1>
  <p>A simple port scanning demo by Go.</p>
</div>


<div align="center" style="text-align: center;">
  <a href="https://www.weizixiang.top">By Karenina-na</a>
</div>

---

**🚀 gmap  is a simple port scanning demo by Go. It can scan the ports of a target host and display the open ports.**

✨ This project is just a demo project, and there are many features yet to be implemented.

---

## ⚗️ Features

- TCP connection scanning
- ICMP Ping scanning
- Scan a single IP address or a range of IP addresses
- CIDR notation support for scanning IP address range
- Multithreaded concurrent scanning for better efficiency
- Save scanning results to a file

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/Karenina-na/gmap.git
```

```bash
# Enter the project directory and run the test
cd gmap
cd test
go test
cd ..
```

```bash
# Build the project (for windows)
go build -trimpath -gcflags="-l=4" -ldflags="-s -w -extldflags '-static'" -o gmap.exe main.go
./gmap.exe
```

## 🚀 Usage Example

ICMP Ping scan an IP range:
```bash
./gmap -m ping -ip 192.168.80.1-254
```

TCP scan a single IP:
```bash
./gmap -m tcp -ip 192.168.80.200 -p 80,8080
```

Specify the output file for results:
```bash
./gmap -m tcp -ip 192.168.80.200 -p 10-100 -o result.txt
```

Multithreaded concurrent scanning:
```bash
./gmap -m ping -ip 192.168.80.1-254 -tc 10 -tm 100 -tt 1000
```

Set the timeout for scanning (ms):
```bash
./gmap -m ping -ip 192.168.80.1-254 -t 1000
```

Set log level:
```bash
./gmap -m ping -ip 192.168.80.1-254 -mode info
```

## 📢 Announcement

I am a novice programmer, brimming with passion for coding, constantly engaged in learning and advancing. This project is the fruit of my learning journey, albeit possibly containing some imperfections. However, I shall persistently refine it and strive to elevate its excellence.

I wholeheartedly welcome everyone's suggestions, opinions, and critiques concerning this project. Should you have any queries or ideas, feel free to engage in a meaningful exchange with me. Together, we shall progress, learn in unison, and mutually inspire one another!"

## 🤝 contribute

1. Contribute to this endeavor, `Fork` the present undertaking.
2. Establish your distinctive branch of characteristics. (`git checkout -b feature/AmazingFeature`)
3. Submit your modifications forthwith. (`git commit -m 'Add some AmazingFeature'`)
4. Propagate your branch to the remote repository with due diligence. (`git push origin feature/AmazingFeature`)
5. Submit a formal pull request for consideration.

## License

[MIT LICENSE](LICENSE)


## 📞 Contact Information

Should you have any questions or concerns regarding the project, please feel free to contact me via the following methods:

- Email: weizixiang0@outlook.com