//go:build !linux && !darwin && !windows

package agentservice

func stopPlatform() (Result, error) {
	return Result{}, nil
}

func startPlatform() (Result, error) {
	return Result{}, nil
}

func uninstallPlatform() error {
	return nil
}
