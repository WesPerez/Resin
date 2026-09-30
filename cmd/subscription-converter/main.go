package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/Resinat/Resin/internal/subscription"
)

const maxInputBytes = 16 * 1024 * 1024

func convert(input io.Reader, output io.Writer) error {
	data, err := io.ReadAll(io.LimitReader(input, maxInputBytes+1))
	if err != nil {
		return errors.New("cannot read subscription input")
	}
	if len(data) > maxInputBytes {
		return errors.New("subscription input exceeds size limit")
	}
	nodes, err := subscription.ParseGeneralSubscription(data)
	if err != nil || len(nodes) == 0 {
		return errors.New("subscription contains no parseable nodes")
	}
	outbounds := make([]json.RawMessage, 0, len(nodes))
	for _, node := range nodes {
		outbounds = append(outbounds, node.RawOptions)
	}
	return json.NewEncoder(output).Encode(struct {
		Outbounds []json.RawMessage `json:"outbounds"`
	}{Outbounds: outbounds})
}

func main() {
	if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: subscription-converter < input > singbox.json")
		os.Exit(2)
	}
	if err := convert(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
