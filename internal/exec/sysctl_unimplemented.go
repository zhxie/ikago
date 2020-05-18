// +build !darwin,!linux,!freebsd

package exec

func disableIPForwarding() error {
	return nil
}
