// Package device receives this test-only hook in the pinned Go checkout.
// It activates the real under-load branch without flooding the UDP socket.
package device

import "time"

// ForceUnderLoadForInterop activates the normal cookie challenge path.
func ForceUnderLoadForInterop(device *Device) {
	device.rate.underLoadUntil.Store(time.Now().Add(30 * time.Second).UnixNano())
}

 
// VerifyNaturalUnderLoadThresholdForInterop exercises the real queue-length
// predicate on an isolated Device without starting worker goroutines.
func VerifyNaturalUnderLoadThresholdForInterop() bool {
	probe := &Device{}
	probe.queue.handshake = &handshakeQueue{
		c: make(chan QueueHandshakeElement, QueueHandshakeSize),
	}
	for i := 0; i < QueueHandshakeSize/8; i++ {
		probe.queue.handshake.c <- QueueHandshakeElement{}
	}
	return probe.IsUnderLoad()
}
