package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"

	"github.com/Bradthebrad/nullbot-emails-mcp/internal/emails"
	"github.com/Bradthebrad/nullbot-emails-mcp/internal/safe"
	"github.com/Bradthebrad/tinychain/mcp"
)

const version = "0.1.0"

func main() {
	transport := flag.String("transport", "stdio", "stdio (default), http or streamable-http; network mode requires authenticated numeric loopback")
	addr := flag.String("addr", "127.0.0.1:8791", "Numeric loopback address for optional local HTTP")
	path := flag.String("path", "/mcp", "Local HTTP MCP path")
	show := flag.Bool("version", false, "Print version and exit")
	flag.Parse()
	if *show {
		fmt.Println("nullbot-emails-mcp", version)
		return
	}
	svc, err := emails.New(os.Getenv("NULLBOT_SERVICE_ACCOUNTS"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "nullbot-emails-mcp: invalid account configuration")
		os.Exit(2)
	}
	token := os.Getenv("NULLBOT_MCP_AUTH_TOKEN")
	svc.Client.Protect(token)
	server := mcp.NewServer("nullbot-emails-mcp")
	server.Version = version
	for _, tool := range svc.Tools() {
		server.AddTool(tool)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := safe.Serve(ctx, server, *transport, *addr, *path, token); err != nil {
		fmt.Fprintln(os.Stderr, "nullbot-emails-mcp:", err)
		os.Exit(1)
	}
}
