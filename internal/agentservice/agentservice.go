package agentservice

// Result beschreibt, ob und wie der Agent-Hintergrunddienst gesteuert wurde.
type Result struct {
	Method  string
	Changed bool
}

// Stop beendet den laufenden ssh-sync-Hintergrunddienst (OS-spezifisch).
func Stop() (Result, error) {
	return stopPlatform()
}

// Start startet den ssh-sync-Hintergrunddienst neu (OS-spezifisch).
func Start() (Result, error) {
	return startPlatform()
}

// Uninstall stoppt den Dienst und entfernt Unit/Service-Registrierung (best effort).
func Uninstall() error {
	return uninstallPlatform()
}
