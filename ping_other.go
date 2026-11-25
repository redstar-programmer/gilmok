//go:build !linux

package main

import (
	"context"
	"errors"
)

// Outside Linux (Gilmok run natively on Windows / macOS for development) there is no unprivileged
// ICMP socket — ping checks report that, TCP / HTTP checks work everywhere.
func pingSupported() bool { return false }

func pingHost(ctx context.Context, host string) error {
	return errors.New("이 환경에서는 ping을 쓸 수 없습니다 — TCP 점검을 쓰세요")
}
