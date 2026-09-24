package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/idrewlong/footprint/pkg/checker"
)

type progress struct {
	w       io.Writer
	live    bool
	label   string
	query   string
	total   int
	done    int
	found   int
	limited int
	failed  int
	width   int
}

func newProgress(w io.Writer, live bool, label, query string, total int) *progress {
	return &progress{w: w, live: live, label: label, query: query, total: total}
}

func (p *progress) start() {
	if !p.live {
		fmt.Fprintln(p.w, p.label)
		return
	}
	p.render()
}

func (p *progress) add(status checker.Status) {
	p.done++
	switch status {
	case checker.StatusFound:
		p.found++
	case checker.StatusRateLimited:
		p.limited++
	case checker.StatusNotFound:
	default:
		p.failed++
	}
	if p.live {
		p.render()
	}
}

func (p *progress) render() {
	line := fmt.Sprintf("%s  %d/%d  %d found  %d rate limited  %d error", p.query, p.done, p.total, p.found, p.limited, p.failed)
	if len(line) < p.width {
		line += strings.Repeat(" ", p.width-len(line))
	}
	p.width = len(line)
	fmt.Fprintf(p.w, "\r%s", line)
}

func (p *progress) finish() {
	if !p.live {
		return
	}
	fmt.Fprintf(p.w, "\r%s\r", strings.Repeat(" ", p.width))
}

func isTerminal(w io.Writer) bool {
	file, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

func useColor(w io.Writer) bool {
	return isTerminal(w) && os.Getenv("NO_COLOR") == ""
}
