// +build !linux

package exec

func disableGRO(_ string) error {
	return nil
}
