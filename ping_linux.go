//go:build linux

package main

// ICMP echo without root: a Linux "ping socket" (SOCK_DGRAM, IPPROTO_ICMP). Docker allows it in
// containers by default (net.ipv4.ping_group_range covers every group); elsewhere it may be off —
// the error then says so and a TCP check is the way out.

import (
	"context"
	"errors"
	"net"
	"syscall"
	"time"
)

func pingSupported() bool {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_ICMP)
	if err != nil {
		return false
	}
	syscall.Close(fd)
	return true
}

func pingHost(ctx context.Context, host string) error {
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", host)
	if err != nil || len(ips) == 0 {
		if err == nil {
			err = errors.New("IPv4 주소 없음")
		}
		return err
	}
	ip := ips[0].To4()
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_ICMP)
	if err != nil {
		return errors.New("이 환경에서는 ping을 쓸 수 없습니다 (ping socket 꺼짐) — TCP 점검을 쓰세요")
	}
	defer syscall.Close(fd)
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(3 * time.Second)
	}
	tv := syscall.NsecToTimeval(time.Until(deadline).Nanoseconds())
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
	// echo request: type 8, code 0, checksum, id (the kernel sets it), seq 1, payload
	pkt := []byte{8, 0, 0, 0, 0, 0, 0, 1, 'g', 'i', 'l', 'm', 'o', 'k'}
	cs := icmpChecksum(pkt)
	pkt[2], pkt[3] = byte(cs>>8), byte(cs)
	sa := &syscall.SockaddrInet4{}
	copy(sa.Addr[:], ip)
	if err := syscall.Sendto(fd, pkt, 0, sa); err != nil {
		return err
	}
	buf := make([]byte, 512)
	for {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
				return errors.New("시간 초과")
			}
			return err
		}
		if n >= 8 && buf[0] == 0 { // echo reply
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("시간 초과")
		}
	}
}

func icmpChecksum(b []byte) uint16 {
	var s uint32
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		s += uint32(b[len(b)-1]) << 8
	}
	for s>>16 != 0 {
		s = s&0xffff + s>>16
	}
	return ^uint16(s)
}
