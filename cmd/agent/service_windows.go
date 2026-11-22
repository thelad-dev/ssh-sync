//go:build windows

package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/user"
	"strings"

	"github.com/kardianos/service"
	"golang.org/x/term"

	"github.com/thelad-dev/ssh-sync/internal/agentconfig"
	"github.com/thelad-dev/ssh-sync/internal/agentservice"
)

const windowsServiceName = "ssh-sync"

type daemonService struct {
	cfgPath string
	stop    chan struct{}
}

func (p *daemonService) Start(s service.Service) error {
	p.stop = make(chan struct{})
	cfg, err := agentconfig.Load(p.cfgPath)
	if err != nil {
		return err
	}
	interval := cfg.PollIntervalSec
	if interval <= 0 {
		interval = 30
	}
	log.Printf("ssh-sync Dienst gestartet (Gerät %s, Intervall %ds)", cfg.DeviceID, interval)
	go runDaemonUntil(cfg, p.stop)
	return nil
}

func (p *daemonService) Stop(s service.Service) error {
	if p.stop != nil {
		select {
		case <-p.stop:
		default:
			close(p.stop)
		}
	}
	return nil
}

func runServiceCommand(cfgPath string, args []string) {
	if len(args) == 0 {
		printServiceUsage()
		os.Exit(1)
	}
	switch args[0] {
	case "run":
		runServiceDaemon(cfgPath, args[1:])
	case "install":
		serviceControl(cfgPath, args[1:], service.ControlAction[3])
	case "uninstall":
		serviceControl(cfgPath, args[1:], service.ControlAction[4])
	case "start":
		serviceControl(cfgPath, args[1:], service.ControlAction[0])
	case "stop":
		serviceControl(cfgPath, args[1:], service.ControlAction[1])
	case "restart":
		serviceControl(cfgPath, args[1:], service.ControlAction[2])
	case "status":
		serviceStatus(cfgPath)
	case "repair":
		serviceRepair(cfgPath, args[1:])
	case "set-logon":
		serviceSetLogon(cfgPath, args[1:])
	case "grant-start":
		serviceGrantStart(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unbekannter service-Befehl: %s\n", args[0])
		printServiceUsage()
		os.Exit(1)
	}
}

func printServiceUsage() {
	fmt.Fprintln(os.Stderr, `Windows-Dienst (als Administrator installieren):

  ssh-sync service install [--user DOMAIN\\name] [--password] [--password-stdin]
  ssh-sync service repair [--user DOMAIN\\name] [--password] [--password-stdin]
  ssh-sync service set-logon [--user DOMAIN\\name] [--password] [--password-stdin]
  ssh-sync service grant-start [--user DOMAIN\\name]   (Admin: Start-Recht + Automatisch)
  ssh-sync service uninstall|start|stop|restart|status
  ssh-sync service run          (intern  -  vom Service-Manager gestartet)

Der Dienst läuft unter deinem Windows-Benutzer (gleiches Konto wie ssh-sync unlock),
damit der Keyring für Hintergrund-Sync erreichbar bleibt. Starttyp: automatisch.

„Zugriff verweigert“ beim start: UAC/Admin nötig  -  ssh-sync versucht RunAs automatisch.
Bei install/repair: Windows-Anmeldepasswort (Dienst-Anmeldung, nicht ssh-sync unlock).`)
}

func runServiceDaemon(cfgPath string, args []string) {
	fs := flag.NewFlagSet("service run", flag.ExitOnError)
	configPath := fs.String("config", cfgPath, "Agent-Config-Pfad")
	_ = fs.Parse(args)

	prg := &daemonService{cfgPath: *configPath}
	svc, err := newWindowsService(*configPath, prg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Service: %v\n", err)
		os.Exit(1)
	}
	if err := svc.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Service: %v\n", err)
		os.Exit(1)
	}
}

func serviceControl(cfgPath string, args []string, action string) {
	fs := flag.NewFlagSet("service "+action, flag.ExitOnError)
	configPath := fs.String("config", cfgPath, "Agent-Config-Pfad")
	runAs := fs.String("user", defaultWindowsServiceUser(), "Windows-Konto für den Dienst")
	password := fs.String("password", "", "Windows-Anmeldepasswort")
	passwordStdin := fs.Bool("password-stdin", false, "Passwort von stdin (eine Zeile, für PowerShell-Pipe)")
	_ = fs.Parse(args)

	askPassword := action == service.ControlAction[3]
	resolvedPassword, err := resolveServicePassword(*runAs, *password, *passwordStdin, askPassword)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Service: %v\n", err)
		os.Exit(1)
	}

	prg := &daemonService{cfgPath: *configPath}
	svc, err := newWindowsServiceWithUser(*configPath, prg, *runAs, resolvedPassword)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Service: %v\n", err)
		os.Exit(1)
	}

	if err := service.Control(svc, action); err != nil {
		if tryRecoverServiceControlErr(action, *configPath, *runAs, err) {
			// elevation oder Hinweis behandelt
		} else {
			fmt.Fprintf(os.Stderr, "service %s: %v\n", action, err)
			switch action {
			case service.ControlAction[3]:
				fmt.Fprintln(os.Stderr, "Tipp: PowerShell als Administrator ausführen.")
			case service.ControlAction[0]:
				if isServiceLogonFailure(err) {
					printServiceLogonHelp(*runAs)
				} else if isServiceAccessDenied(err) {
					printServiceAccessDeniedHelp()
				}
			case service.ControlAction[1], service.ControlAction[2]:
				if isServiceAccessDenied(err) {
					printServiceAccessDeniedHelp()
				}
			}
			os.Exit(1)
		}
	}

	if action == service.ControlAction[3] {
		configureServiceAfterInstall(*runAs)
		if *runAs != "" && resolvedPassword != "" {
			if err := setWindowsServiceLogon(*runAs, resolvedPassword); err != nil {
				fmt.Fprintf(os.Stderr, "Warnung: Dienst-Konto per sc.exe: %v\n", err)
				fmt.Fprintln(os.Stderr, "Falls start fehlschlägt: Passwort in services.msc setzen oder ssh-sync service repair")
			}
		}
	}

	switch action {
	case service.ControlAction[3]:
		fmt.Printf("Dienst %q installiert (Konto: %s).\n", windowsServiceName, *runAs)
		fmt.Println("Nächster Schritt: ssh-sync unlock && ssh-sync service start")
	case service.ControlAction[4]:
		fmt.Println("Dienst deinstalliert.")
	default:
		fmt.Printf("Dienst: %s ok\n", action)
	}
}

func serviceStatus(cfgPath string) {
	prg := &daemonService{cfgPath: cfgPath}
	svc, err := newWindowsService(cfgPath, prg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Service: %v\n", err)
		os.Exit(1)
	}
	status, err := svc.Status()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Status: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Dienst %s: %s\n", windowsServiceName, status)
}

func newWindowsService(cfgPath string, prg *daemonService) (service.Service, error) {
	return newWindowsServiceWithUser(cfgPath, prg, defaultWindowsServiceUser(), "")
}

func serviceRepair(cfgPath string, args []string) {
	fmt.Println("→ Dienst neu einrichten (deinstallieren + installieren mit Passwort)")
	_ = serviceControlQuiet(cfgPath, args, service.ControlAction[4])
	serviceControl(cfgPath, args, service.ControlAction[3])
}

func serviceSetLogon(cfgPath string, args []string) {
	fs := flag.NewFlagSet("service set-logon", flag.ExitOnError)
	_ = fs.String("config", cfgPath, "Agent-Config-Pfad")
	runAs := fs.String("user", defaultWindowsServiceUser(), "Windows-Konto für den Dienst")
	password := fs.String("password", "", "Windows-Anmeldepasswort")
	passwordStdin := fs.Bool("password-stdin", false, "Passwort von stdin")
	_ = fs.Parse(args)

	pw, err := resolveServicePassword(*runAs, *password, *passwordStdin, true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Service: %v\n", err)
		os.Exit(1)
	}
	if err := setWindowsServiceLogon(*runAs, pw); err != nil {
		fmt.Fprintf(os.Stderr, "set-logon: %v\n", err)
		os.Exit(1)
	}
	configureServiceAfterInstall(*runAs)
	fmt.Printf("Dienst-Anmeldung für %s gesetzt.\n", *runAs)
	fmt.Println("Nächster Schritt: ssh-sync service start")
}

func serviceGrantStart(args []string) {
	fs := flag.NewFlagSet("service grant-start", flag.ExitOnError)
	runAs := fs.String("user", defaultWindowsServiceUser(), "Windows-Konto")
	_ = fs.Parse(args)
	if err := grantServiceControlToAccount(*runAs); err != nil {
		fmt.Fprintf(os.Stderr, "grant-start: %v\n", err)
		fmt.Fprintln(os.Stderr, "Tipp: PowerShell als Administrator ausführen.")
		os.Exit(1)
	}
	_ = exec.Command("sc.exe", "config", windowsServiceName, "start=", "auto").Run()
	fmt.Printf("Start-Recht für %s gesetzt, Starttyp automatisch.\n", *runAs)
}

func serviceControlQuiet(cfgPath string, args []string, action string) error {
	fs := flag.NewFlagSet("service "+action, flag.ExitOnError)
	configPath := fs.String("config", cfgPath, "Agent-Config-Pfad")
	runAs := fs.String("user", defaultWindowsServiceUser(), "Windows-Konto für den Dienst")
	password := fs.String("password", "", "Windows-Anmeldepasswort")
	_ = fs.Parse(args)
	prg := &daemonService{cfgPath: *configPath}
	svc, err := newWindowsServiceWithUser(*configPath, prg, *runAs, *password)
	if err != nil {
		return err
	}
	return service.Control(svc, action)
}

func tryRecoverServiceControlErr(action, cfgPath, runAs string, err error) bool {
	if action != service.ControlAction[0] && action != service.ControlAction[1] && action != service.ControlAction[2] {
		return false
	}
	if !isServiceAccessDenied(err) {
		return false
	}
	cmdName := map[string]string{
		service.ControlAction[0]: "start",
		service.ControlAction[1]: "stop",
		service.ControlAction[2]: "restart",
	}[action]
	fmt.Fprintln(os.Stderr, "→ Zugriff verweigert  -  versuche Start als Administrator (UAC) …")
	if tryElevatedServiceControl(cfgPath, cmdName) {
		fmt.Printf("Dienst: %s ok (als Administrator)\n", cmdName)
		return true
	}
	return false
}

func isServiceAccessDenied(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "access denied") ||
		strings.Contains(s, "zugriff verweigert") ||
		strings.Contains(s, "error 5") ||
		strings.Contains(s, "exit status 5")
}

func isServiceLogonFailure(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "logon") ||
		strings.Contains(s, "anmeldung") ||
		strings.Contains(s, "1069") ||
		strings.Contains(s, "fehlerhafte")
}

func printServiceAccessDeniedHelp() {
	exe, _ := os.Executable()
	fmt.Fprintf(os.Stderr, `
Ursache: Dienste starten/stoppen erfordert unter Windows oft Administrator-Rechte.

Sofort (UAC-Abfrage):
  Start-Process -FilePath '%s' -ArgumentList 'service','start' -Verb RunAs

Oder PowerShell „Als Administrator“ öffnen:
  ssh-sync service start

Dauerhaft: Dienst auf „Automatisch“ (startet nach Anmeldung/Neustart):
  services.msc → SSH Profile Syncer → Starttyp: Automatisch
`, exe)
}

func tryElevatedServiceControl(cfgPath, subCmd string) bool {
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	script := fmt.Sprintf(`
$ErrorActionPreference = 'Stop'
$p = Start-Process -FilePath %q -ArgumentList @('service',%q,'--config',%q) -Verb RunAs -Wait -PassThru
exit $p.ExitCode
`, exe, subCmd, cfgPath)
	cmd := exec.Command("powershell.exe", "-NoProfile", "-Command", script)
	if err := cmd.Run(); err != nil {
		return false
	}
	return true
}

func configureServiceAfterInstall(runAs string) {
	_ = exec.Command("sc.exe", "config", windowsServiceName, "start=", "auto").Run()
	if err := grantServiceControlToAccount(runAs); err != nil {
		fmt.Fprintf(os.Stderr, "Hinweis: Start-Berechtigung für %s: %v\n", runAs, err)
		fmt.Fprintln(os.Stderr, "Start ggf. als Administrator: ssh-sync service start")
	}
}

func grantServiceControlToAccount(account string) error {
	if account == "" {
		return nil
	}
	escaped := strings.ReplaceAll(account, "'", "''")
	script := fmt.Sprintf(`
$ErrorActionPreference = 'Stop'
$name = '%s'
$acct = '%s'
$sid = (New-Object System.Security.Principal.NTAccount($acct)).Translate([System.Security.Principal.SecurityIdentifier]).Value
$raw = ((sc.exe sdshow $name 2>&1 | Out-String).Trim()) -replace "[\r\n]", ''
if ($raw -match [regex]::Escape($sid)) { exit 0 }
$ace = "(A;;RPWPLC;;;$sid)"
if ($raw -match '^D:') {
  $new = $raw -replace '^D:', ('D:' + $ace)
} else {
  $new = 'D:' + $ace + $raw
}
$null = sc.exe sdset $name $new
`, windowsServiceName, escaped)
	cmd := exec.Command("powershell.exe", "-NoProfile", "-Command", script)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			return fmt.Errorf("%w: %s", err, msg)
		}
		return err
	}
	return nil
}

func printServiceLogonHelp(runAs string) {
	fmt.Fprintln(os.Stderr, `
Ursache: Windows hat kein gültiges Passwort für das Dienst-Konto gespeichert
(„fehlerhafte Anmeldung“ / Logon failure).

Als Administrator in derselben PowerShell:
  ssh-sync service repair`+serviceUserHint(runAs)+`
  ssh-sync unlock
  ssh-sync service start

Hinweis: Bei der Installation muss das Windows-Anmeldepasswort
für das Dienst-Konto eingegeben werden  -  nicht das ssh-sync Master-Passwort.`)
}

func serviceUserHint(runAs string) string {
	if runAs == "" {
		return ""
	}
	return " --user " + runAs
}

func resolveServicePassword(runAs, flagPassword string, fromStdin, ask bool) (string, error) {
	if flagPassword != "" {
		fmt.Fprintln(os.Stderr, "Warnung: --password erscheint in der Prozessliste; besser --password-stdin oder interaktiver Dialog")
		return flagPassword, nil
	}
	if fromStdin {
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			return "", fmt.Errorf("stdin lesen: %w", err)
		}
		pw := strings.TrimSpace(string(b))
		if pw == "" {
			return "", fmt.Errorf("leeres Passwort auf stdin")
		}
		return pw, nil
	}
	if !ask || runAs == "" {
		return "", nil
	}
	return promptWindowsServicePassword(runAs)
}

// setWindowsServiceLogon setzt Konto+Passwort per sc.exe (zuverlässiger als reine kardianos-Übergabe).
func setWindowsServiceLogon(runAs, password string) error {
	cmd := exec.Command("sc.exe", "config", windowsServiceName, "obj=", runAs, "password=", password)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			return fmt.Errorf("%w: %s", err, msg)
		}
		return err
	}
	return nil
}

func newWindowsServiceWithUser(cfgPath string, prg *daemonService, runAs, password string) (service.Service, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	opt := service.KeyValue{"StartType": "automatic"}
	if runAs != "" && password != "" {
		opt["Password"] = password
	}
	cfg := &service.Config{
		Name:        windowsServiceName,
		DisplayName: "SSH Profile Syncer",
		Description: "Synchronisiert SSH-Config vom zentralen ssh-sync Server",
		Executable:  exe,
		Arguments:   []string{"service", "run", "--config", cfgPath},
		UserName:    runAs,
		Option:      opt,
	}
	return service.New(prg, cfg)
}

func defaultWindowsServiceUser() string {
	if domain := os.Getenv("USERDOMAIN"); domain != "" {
		if user := os.Getenv("USERNAME"); user != "" {
			return domain + `\` + user
		}
	}
	u, err := user.Current()
	if err != nil {
		return ""
	}
	if strings.Contains(u.Username, `\`) {
		return u.Username
	}
	return u.Username
}

func promptWindowsServicePassword(runAs string) (string, error) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(os.Stderr, "Windows-Anmeldepasswort für "+runAs+" (Dienst-Konto): ")
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err == nil && len(b) > 0 {
			return string(b), nil
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Konsole: %v  -  wechsle zu Anmeldedialog\n", err)
		}
	}
	pw, err := promptWindowsPasswordCredentialUI(runAs)
	if err != nil {
		return "", fmt.Errorf("Windows-Anmeldepasswort erforderlich für %s: %w", runAs, err)
	}
	return pw, nil
}

// promptWindowsPasswordCredentialUI nutzt den Windows-Anmeldedialog (funktioniert in CMD/PowerShell).
func promptWindowsPasswordCredentialUI(username string) (string, error) {
	escaped := strings.ReplaceAll(username, "'", "''")
	script := fmt.Sprintf(`
$ErrorActionPreference = 'Stop'
$c = Get-Credential -UserName '%s' -Message 'Windows-Passwort für ssh-sync Dienst (nicht ssh-sync Master-Passwort)'
if ($null -eq $c) { exit 2 }
$b = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($c.Password)
try {
  [Runtime.InteropServices.Marshal]::PtrToStringAuto($b)
} finally {
  [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b)
}
`, escaped)
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	out, err := cmd.Output()
	if err != nil {
		if exit, ok := err.(*exec.ExitError); ok && exit.ExitCode() == 2 {
			return "", fmt.Errorf("abgebrochen")
		}
		return "", err
	}
	pw := strings.TrimSpace(string(out))
	if pw == "" {
		return "", fmt.Errorf("leeres Passwort")
	}
	return pw, nil
}

func stopAgentService() {
	res, err := agentservice.Stop()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Dienst stoppen: %v\n", err)
		return
	}
	if res.Changed {
		fmt.Printf("Dienst gestoppt (%s)\n", res.Method)
	}
}

func startAgentService() {
	res, err := agentservice.Start()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Dienst starten: %v\n", err)
		return
	}
	if res.Changed {
		fmt.Printf("Dienst gestartet (%s)\n", res.Method)
	}
}
