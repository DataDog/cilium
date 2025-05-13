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
	fmt.Printf("function: %+v\n", function)
	resourceName := function.Name()
	fmt.Printf("function.Name(): %+v\n", resourceName)
	if len(strings.Split(resourceName, ".")) > 3 {
		resourceName = strings.Split(resourceName, ".")[3]
	}
	fmt.Printf("resourceName: %s\n", resourceName)

	return tracer.StartSpanFromContext(
		ctx,
		"cilium.TODO",
		tracer.ResourceName(resourceName),
		tracer.ServiceName("cilium-operator"),
	)
}
