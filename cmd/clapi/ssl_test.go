package clapi

import (
	"context"
	"flag"
	"strings"
	"testing"

	"bitbucket.org/letsencrypt-cpanel/letsencrypt-cpanel/cmd/common/pb"
	"google.golang.org/grpc"
	"gopkg.in/urfave/cli.v1"
)

type failedRenewalClient struct {
	pb.PluginClient
	request *pb.SSLDoRenewalsRequest
}

func (c *failedRenewalClient) SSLDoRenewals(ctx context.Context, in *pb.SSLDoRenewalsRequest, opts ...grpc.CallOption) (*pb.SSLDoRenewalsResponse, error) {
	c.request = in
	return &pb.SSLDoRenewalsResponse{Errors: []*pb.Error{{Error: "Dry-run failed for example.test: Domain mail.example.test failed DCV"}}}, nil
}

func TestRenewalDryRunReturnsRPCFailure(t *testing.T) {
	savedClient, savedContext := cl, clCtx
	t.Cleanup(func() { cl, clCtx = savedClient, savedContext })
	client := &failedRenewalClient{}
	cl, clCtx = client, context.Background()
	flags := flag.NewFlagSet("renew", flag.ContinueOnError)
	flags.String("user", "test-account", "")
	flags.String("virtualhost", "example.test", "")
	flags.Bool("dry-run", true, "")
	flags.Bool("force", false, "")
	err := renewUserSSL(cli.NewContext(cli.NewApp(), flags, nil))
	if err == nil || !strings.Contains(err.Error(), "mail.example.test") {
		t.Fatalf("RPC failure was hidden: %v", err)
	}
	if client.request == nil || !client.request.DryRun || client.request.User != "test-account" || client.request.VirtualHost != "example.test" {
		t.Fatalf("request=%v", client.request)
	}
}
