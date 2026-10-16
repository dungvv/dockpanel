package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"

	"golang.org/x/term"
)

// resolvePassword picks the password from --password, --password-stdin, or
// (when neither is given) a masked prompt on the controlling terminal.
//
// A bare --password VALUE lands in shell history and stays visible to any
// local user via ps//proc/<pid>/cmdline for the life of the process — this
// exists so that door is opt-in rather than the only one.
func resolvePassword(password *string, fromStdin bool, prompt string) (string, error) {
	if password != nil {
		return *password, nil
	}
	if fromStdin {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && err != io.EOF {
			return "", fmt.Errorf("Failed to read password from stdin: %s", ioErr(err))
		}
		if !utf8.ValidString(line) {
			return "", errors.New("Failed to read password from stdin: stream did not contain valid UTF-8")
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			return "", errors.New("Password read from stdin was empty")
		}
		return line, nil
	}
	p, err := promptTTY(prompt)
	if err != nil {
		return "", fmt.Errorf("Failed to read password: %s", err)
	}
	if p == "" {
		return "", errors.New("Password must not be empty")
	}
	return p, nil
}

// promptTTY behaves like rpassword::prompt_password: prompt and read on
// /dev/tty (not stdout/stdin), echo off, newline echoed after.
func promptTTY(prompt string) (string, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", errors.New(ioErr(err))
	}
	defer tty.Close()
	if _, err := tty.WriteString(prompt); err != nil {
		return "", errors.New(ioErr(err))
	}
	b, err := term.ReadPassword(int(tty.Fd()))
	tty.WriteString("\n")
	if err == io.EOF {
		return "", errors.New("unexpected end of file")
	}
	if err != nil {
		return "", errors.New(ioErr(err))
	}
	return string(b), nil
}

// randByte reads one byte from /dev/urandom. It errors rather than silently
// returning 0 — a swallowed failure here once made every generated password
// the fully predictable "aaaaaaaaaaaaaaaa".
func randByte() (byte, error) {
	f, err := os.Open("/dev/urandom")
	if err != nil {
		return 0, fmt.Errorf("Cannot open /dev/urandom for password generation: %s", ioErr(err))
	}
	defer f.Close()
	var b [1]byte
	if _, err := io.ReadFull(f, b[:]); err != nil {
		return 0, fmt.Errorf("Cannot read /dev/urandom for password generation: %s", ioErr(err))
	}
	return b[0], nil
}

func cmdDBList(token, output string, filter *string) error {
	v, err := agentGet("/databases", token)
	if err != nil {
		return err
	}
	dbs, ok := arr(v)
	if !ok {
		return errors.New("Expected array from /databases")
	}
	filtered := []any{}
	for _, d := range dbs {
		if filter == nil || containsFold(strOr(get(d, "name"), ""), *filter) {
			filtered = append(filtered, d)
		}
	}
	if output == "json" {
		fmt.Println(pretty(filtered))
		return nil
	}
	if len(filtered) == 0 {
		fmt.Println("No databases.")
		return nil
	}
	fmt.Printf("\x1b[1m%-20s %-12s %-8s %-12s\x1b[0m\n", "NAME", "ENGINE", "PORT", "STATUS")
	for _, d := range filtered {
		status := strOr(get(d, "status"), "-")
		color := "\x1b[31m"
		if status == "running" {
			color = "\x1b[32m"
		}
		fmt.Printf("%-20s %-12s %-8d %s%-12s\x1b[0m\n", strOr(get(d, "name"), "-"), strOr(get(d, "engine"), "-"), u64Or(get(d, "port"), 0), color, status)
	}
	fmt.Printf("\n%d database(s)\n", len(filtered))
	return nil
}

func cmdDBCreate(token, name, engine string, password *string, fromStdin bool, port int64) error {
	switch engine {
	case "mysql", "mariadb", "postgres":
	default:
		return fmt.Errorf("Invalid engine '%s'. Use: mysql, mariadb, or postgres", engine)
	}
	pw, err := resolvePassword(password, fromStdin, "Root/admin password: ")
	if err != nil {
		return err
	}
	fmt.Printf("Creating %s database '%s' on port %d...\n", engine, name, port)
	result, err := agentPost("/databases", map[string]any{"name": name, "engine": engine, "password": pw, "port": port}, token)
	if err != nil {
		return err
	}
	if !isTrue(get(result, "success")) {
		return fmt.Errorf("Failed to create database: %s", strOr(get(result, "message"), "Unknown error"))
	}
	fmt.Println("\x1b[32m✓\x1b[0m Database created")
	fmt.Printf("  Name:         %s\n", name)
	fmt.Printf("  Engine:       %s\n", engine)
	fmt.Printf("  Port:         %d\n", port)
	fmt.Printf("  Container:    %s\n", shortID(strOr(get(result, "container_id"), "unknown")))
	return nil
}

func cmdDBDelete(token, containerID string) error {
	fmt.Printf("Deleting database container %s...\n", containerID)
	result, err := agentDelete("/databases/"+containerID, token)
	if err != nil {
		return err
	}
	if !isTrue(get(result, "success")) {
		return fmt.Errorf("Failed to delete database: %s", strOr(get(result, "message"), "Unknown error"))
	}
	fmt.Println("\x1b[32m✓\x1b[0m Database deleted")
	return nil
}
