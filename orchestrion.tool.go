//go:build tools

//go:generate go run github.com/DataDog/orchestrion pin -generate

package tools

// Curated Datadog instrumentation set. We deliberately do NOT import the
// catch-all github.com/DataDog/dd-trace-go/orchestrion/all/v2: it enables ~40
// integrations (kafka, redis, mongo, graphql, gin, chi, echo, fiber, vault,
// pgx, gocql, elasticsearch, ...) for libraries cilium doesn't use. Instead we
// import only the integrations whose target libraries are actually in cilium's
// dependency graph.
import (
	_ "github.com/DataDog/orchestrion" // integration

	_ "github.com/DataDog/dd-trace-go/v2/ddtrace/tracer" // integration
	_ "github.com/DataDog/dd-trace-go/v2/orchestrion"    // integration

	// Integrations for libraries cilium actually uses.
	_ "github.com/DataDog/dd-trace-go/contrib/aws/aws-sdk-go-v2/v2/aws"       // integration
	_ "github.com/DataDog/dd-trace-go/contrib/google.golang.org/grpc/v2"      // integration
	_ "github.com/DataDog/dd-trace-go/contrib/k8s.io/client-go/v2/kubernetes" // integration
	_ "github.com/DataDog/dd-trace-go/contrib/log/slog/v2"                    // integration
	_ "github.com/DataDog/dd-trace-go/contrib/net/http/v2"                    // integration
	_ "github.com/DataDog/dd-trace-go/contrib/sirupsen/logrus/v2"             // integration
)
