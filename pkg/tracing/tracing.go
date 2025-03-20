package tracing

import (
	"context"
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
	return tracer.StartSpanFromContext(
		ctx,
		"cilium.TODO",
		tracer.ResourceName(strings.Split(function.Name(), ".")[3]),
		tracer.ServiceName("cilium-operator"),
	)
}
