//go:build tools

//go:generate go run github.com/DataDog/orchestrion pin -generate

package tools

import (
	_ "github.com/DataDog/dd-trace-go/orchestrion/all/v2" // integration
	_ "github.com/DataDog/orchestrion"                    // integration
)
