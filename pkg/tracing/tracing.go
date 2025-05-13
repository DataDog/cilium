package tracing

import (
	"context"
	"fmt"
	"runtime"
	"strings"

	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace/tracer"
)

var WithError = tracer.WithError

func StartSpan(ctx context.Context) (tracer.Span, context.Context) {
	// We inspect the callstack to get the name of the calling function
	programCounters := make([]uintptr, 1)
	runtime.Callers(2, programCounters)
	function := runtime.FuncForPC(programCounters[0])
	functionName := function.Name()
	functionName = strings.TrimPrefix(functionName, "github.com/cilium/cilium/")
	functionParts := strings.Split(functionName, ".")
	pkg := functionParts[0]
	resourceName := "placeholder"
	if len(functionParts) == 2 {
		resourceName = functionParts[1]
	} else if len(functionParts) > 2 {
		resourceName = fmt.Sprintf("%s.%s", functionParts[1], functionParts[2])
	}

	return tracer.StartSpanFromContext(
		ctx,
		pkg,
		tracer.ResourceName(resourceName),
		tracer.ServiceName("cilium-operator"),
	)
}
