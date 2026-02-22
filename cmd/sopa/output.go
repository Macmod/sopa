package main

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/Macmod/go-adws/soap"
	"github.com/mattn/go-isatty"
)

type Printer struct {
	out     io.Writer
	noColor bool
	color   bool
}

func NewPrinter(out io.Writer, noColor bool) *Printer {
	p := &Printer{out: out, noColor: noColor}
	p.color = p.shouldColor()
	return p
}

func (p *Printer) shouldColor() bool {
	if p == nil || p.noColor {
		return false
	}
	if strings.TrimSpace(os.Getenv("NO_COLOR")) != "" {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(os.Getenv("TERM")), "dumb") {
		return false
	}
	if strings.TrimSpace(os.Getenv("SOPA_FORCE_COLOR")) == "1" {
		return true
	}

	f, ok := p.out.(*os.File)
	if !ok {
		return false
	}
	return isatty.IsTerminal(f.Fd()) || isatty.IsCygwinTerminal(f.Fd())
}

func (p *Printer) Fprintf(format string, args ...any) {
	if p == nil || p.out == nil {
		return
	}
	_, _ = fmt.Fprintf(p.out, format, args...)
}

func (p *Printer) Infof(format string, args ...any) {
	p.Fprintf(format, args...)
}

func (p *Printer) Successf(format string, args ...any) {
	prefix := "[+] "
	if p.color {
		prefix = ansi(32, "[+]") + " "
	}
	p.Fprintf(prefix+format, args...)
}

func (p *Printer) Donef(format string, args ...any) {
	prefix := "✓ "
	if p.color {
		prefix = ansi(32, "✓") + " "
	}
	p.Fprintf(prefix+format, args...)
}

func (p *Printer) Label(label string) string {
	if !p.color {
		return label
	}
	return ansi(36, label)
}

func (p *Printer) Key(key string) string {
	if !p.color {
		return key
	}
	return ansi(32, key)
}

func (p *Printer) Dim(s string) string {
	if !p.color {
		return s
	}
	return ansi(2, s)
}

func (p *Printer) PrintItem(item *soap.ADWSItem) {
	if p == nil || item == nil {
		return
	}

	if item.DistinguishedName != "" {
		p.Fprintf("%s %s\n", p.Label("DN:"), item.DistinguishedName)
	}

	keys := make([]string, 0, len(item.Attributes))
	for k := range item.Attributes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		vals := item.Attributes[k]
		if len(vals) == 0 {
			continue
		}

		parts := make([]string, 0, len(vals))
		for _, v := range vals {
			parts = append(parts, v.Value)
		}

		syntax := vals[0].LdapSyntax
		if syntax != "" {
			p.Fprintf("  %s %s %s\n", p.Key(k), p.Dim("("+syntax+")"), strings.Join(parts, "; "))
		} else {
			p.Fprintf("  %s: %s\n", p.Key(k), strings.Join(parts, "; "))
		}
	}
}

func ansi(code int, s string) string {
	return fmt.Sprintf("\x1b[%dm%s\x1b[0m", code, s)
}
