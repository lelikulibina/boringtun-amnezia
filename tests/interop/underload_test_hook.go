// Package device receives this test-only hook in the pinned Go checkout.
// It activates the real under-load branch without flooding the UDP socket.
package device

import "time"

// ForceUnderLoadForInterop activates the normal cookie challenge path.
func ForceUnderLoadForInterop(device *Device) {
	device.rate.underLoadUntil.Store(time.Now().Add(30 * time.Second).UnixNano())
}
