# Network Sniffer with Golang
Simple implementation of Sniffer with Golang

Features:
- [x] Shows list of all available devices
- [x] Support GTK+
- [ ] Provides interface for choosing one of the devices
- [x] Catches packages in a loop on selected device

## How to work with the sniffer:
### Build
```
go build  -ldflags -s ./main.go
```
### Run
```
sudo ./main
```
You can specify params for the 