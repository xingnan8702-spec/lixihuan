package netutil

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

type DeadlineConn struct {
	net.Conn
	Timeout time.Duration
}

func (c DeadlineConn) Read(p []byte) (int, error) {
	if c.Timeout > 0 {
		_ = c.SetReadDeadline(time.Now().Add(c.Timeout))
	}
	return c.Conn.Read(p)
}
func (c DeadlineConn) Write(p []byte) (int, error) {
	if c.Timeout > 0 {
		_ = c.SetWriteDeadline(time.Now().Add(c.Timeout))
	}
	return c.Conn.Write(p)
}

type closeWriter interface{ CloseWrite() error }

func Relay(a, b net.Conn, timeout time.Duration) error {
	aio := DeadlineConn{Conn: a, Timeout: timeout}
	bio := DeadlineConn{Conn: b, Timeout: timeout}
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	copyOne := func(dst DeadlineConn, closeDst net.Conn, src DeadlineConn) {
		defer wg.Done()
		_, err := io.Copy(dst, src)
		if cw, ok := closeDst.(closeWriter); ok {
			_ = cw.CloseWrite()
		}
		errs <- err
	}
	wg.Add(2)
	go copyOne(aio, a, bio)
	go copyOne(bio, b, aio)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil && !errors.Is(err, net.ErrClosed) {
			return err
		}
	}
	return nil
}
