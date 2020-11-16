package gtpu

import (
	"os"
	"syscall"
	"unsafe"
)

func getTunFile(ifname string) (*os.File, error) {
	ifreq := struct {
		name  [syscall.IFNAMSIZ]byte // c string
		flags uint16                 // c short
		_pad  [24 - unsafe.Sizeof(uint16(0))]byte
	}{}
	copy(ifreq.name[:], []byte(ifname))
	ifreq.flags = syscall.IFF_TUN | syscall.IFF_NO_PI

	f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0600)
	if err == nil {
		_, _, e := syscall.Syscall(
			syscall.SYS_IOCTL,
			f.Fd(),
			syscall.TUNSETIFF,
			uintptr(unsafe.Pointer(&ifreq)))
		if e != 0 {
			f.Close()
			f = nil
			err = os.NewSyscallError("ioctl", e)
		}
	}
	return f, err
}
