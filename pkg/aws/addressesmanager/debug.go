package addressesmanager

import (
	"time"
)

var (
	SuccessfulSmartIPAllocate int
	FailedSmartIPAllocate     int

	SuccessfulSmartENICreate int
	FailedSmartENICreate     int

	StartTime = time.Now()
)

func startTicker() {
	// Create a new ticker that triggers every 5 minutes
	ticker := time.NewTicker(5 * time.Minute)

	go func() {
		// Use an infinite loop to continuously check for ticker events
		for {
			select {
			case <-ticker.C:
				// This block executes every 5 minutes
				totalAllocations := SuccessfulSmartIPAllocate + FailedSmartIPAllocate
				totalENICreation := SuccessfulSmartENICreate + FailedSmartENICreate

				if totalAllocations != 0 {
					log.Infof("Running for %s, IP allocations: %d OK (%v%%), %d KO (%v%%)",
						time.Since(StartTime),

						SuccessfulSmartIPAllocate,
						100*float32(SuccessfulSmartIPAllocate)/float32(totalAllocations),
						FailedSmartIPAllocate,
						100*float32(FailedSmartIPAllocate)/float32(totalAllocations),
					)
				}
				if totalENICreation != 0 {
					log.Infof("Running for %s, ENI creations: %v OK (%v%%), %v KO (%v%%)",
						time.Since(StartTime),

						SuccessfulSmartENICreate,
						100*float32(SuccessfulSmartENICreate)/float32(totalENICreation),
						FailedSmartENICreate,
						100*float32(FailedSmartENICreate)/float32(totalENICreation),
					)
				}
			}
		}
	}()
}

func init() {
	startTicker()
}
