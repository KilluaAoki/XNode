package xray

import (
	"context"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
	"golang.org/x/time/rate"
)

func waitRate(lim *rate.Limiter, n int) error {
	for n > 0 {
		b := lim.Burst()
		if b <= 0 {
			return nil
		}
		k := min(n, b)
		if err := lim.WaitN(context.Background(), k); err != nil {
			return err
		}
		n -= k
	}
	return nil
}

type rateLimitWriter struct {
	buf.Writer
	limiter *rate.Limiter
}

func (w *rateLimitWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if err := waitRate(w.limiter, int(mb.Len())); err != nil {
		buf.ReleaseMulti(mb)
		return err
	}
	return w.Writer.WriteMultiBuffer(mb)
}

func (w *rateLimitWriter) Close() error { return common.Close(w.Writer) }

func (w *rateLimitWriter) Interrupt() { common.Interrupt(w.Writer) }

type rateLimitReader struct {
	buf.Reader
	limiter *rate.Limiter
}

func (r *rateLimitReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb, err := r.Reader.ReadMultiBuffer()
	if n := int(mb.Len()); n > 0 {
		_ = waitRate(r.limiter, n)
	}
	return mb, err
}

func (r *rateLimitReader) Close() error { return common.Close(r.Reader) }

func (r *rateLimitReader) Interrupt() { common.Interrupt(r.Reader) }

func limitDispatchedLink(ctx context.Context, link *transport.Link, lim *rate.Limiter) *transport.Link {
	reader, writer := pipe.New(pipe.OptionsFromContext(ctx)...)
	src := link.Reader
	go func() {
		if err := buf.Copy(src, &rateLimitWriter{Writer: writer, limiter: lim}); err != nil {
			common.Interrupt(src)
			common.Interrupt(writer)
			return
		}
		common.Close(writer)
	}()
	return &transport.Link{
		Reader: reader,
		Writer: &rateLimitWriter{Writer: link.Writer, limiter: lim},
	}
}

func limitInboundLink(link *transport.Link, lim *rate.Limiter) {
	link.Reader = &rateLimitReader{Reader: link.Reader, limiter: lim}
	link.Writer = &rateLimitWriter{Writer: link.Writer, limiter: lim}
}
