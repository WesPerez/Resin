package proxy

import (
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// A lease guard is an absolute lifetime, independent of transport deadlines.
// WebSocket-backed outbounds may reject SetDeadline; extending or clearing an
// I/O deadline must not extend the account's authorization either.
type guardDeadlineConn struct {
	net.Conn
	mu       sync.Mutex
	timer    *time.Timer
	once     sync.Once
	expired  atomic.Bool
	closeErr error
}

func newGuardDeadlineConn(conn net.Conn, until time.Time) *guardDeadlineConn {
	c := &guardDeadlineConn{Conn: conn}
	c.mu.Lock()
	c.timer = time.AfterFunc(time.Until(until), func() { _ = c.close(true) })
	c.mu.Unlock()
	return c
}

func (c *guardDeadlineConn) close(expired bool) error {
	c.once.Do(func() {
		c.expired.Store(expired)
		c.mu.Lock()
		c.timer.Stop()
		c.mu.Unlock()
		c.closeErr = c.Conn.Close()
	})
	return c.closeErr
}

func (c *guardDeadlineConn) Close() error      { return c.close(false) }
func (c *guardDeadlineConn) CloseWrite() error { return closeWriteErr(c.Conn) }
func (c *guardDeadlineConn) CloseRead() error  { return closeReadErr(c.Conn) }
