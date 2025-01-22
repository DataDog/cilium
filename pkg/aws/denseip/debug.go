package denseip

import (
	"time"
)

var (
	SuccessfulSmartIPAllocate int
	FailedSmartIPAllocate     int

	SuccessfulSmartENICreate int
	FailedfulSmartENICreate  int

	StartTime = time.Now()
)

func init() {
	// Create a new ticker that triggers every 5 minutes
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop() // Ensure the ticker is stopped when no longer needed

	// Use an infinite loop to continuously check for ticker events
	for {
		select {
		case <-ticker.C:
			// This block executes every 5 minutes
			totalAllocations := SuccessfulSmartIPAllocate + FailedSmartIPAllocate
			totalENICreation := SuccessfulSmartENICreate + FailedfulSmartENICreate
			if totalAllocations == 0 || totalENICreation == 0 {
				continue
			}
			log.Infof("Running for %s, IP allocations: %d OK (%v%%), %d KO (%v%%), ENI creations: %v OK (%v%%), %v KO (%v%%)",
				time.Since(StartTime),

				SuccessfulSmartIPAllocate,
				100*float32(SuccessfulSmartIPAllocate)/float32(totalAllocations),
				FailedSmartIPAllocate,
				100*float32(FailedSmartIPAllocate)/float32(totalAllocations),

				SuccessfulSmartENICreate,
				100*float32(SuccessfulSmartENICreate)/float32(totalENICreation),
				FailedfulSmartENICreate,
				100*float32(FailedfulSmartENICreate)/float32(totalENICreation),
			)
		}
	}
}
