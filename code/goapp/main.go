//go:build linux || darwin || windows
// +build linux darwin windows

// +build后可以跟多个平台，用空格隔开表示或，用逗号分隔表示与
// linux darwin windows：表示linux darwin windows都可以编译
// linux,386: 表示Linux并且是386平台才可以编译
// 参考：https://www.gitdig.com/post/2019-07-08-go-comment/
package main

import (
	"fmt"
	"nlenc"
	"github.com/vishvananda/netlink"
)
const (
	netlinkCustom = 31
)

conn, err := netlink.Dial(netlinkCustom, nil)
func main() {
	msg:="hi"
	data := make([]byte, 4+len(msg)+1)
	nlenc.PutUint32(data[:4], uint32(len(msg)+1))
	copy(data[4:], msg)

	fmt.Println("Send to kernel:", msg)

	var nlmsg netlink.Message
	nlmsg.Data = data

	msgs, err := conn.Execute(nlmsg)
}
