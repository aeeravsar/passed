package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/term"
	"passed/internal/crypto"
	"passed/internal/mnemonic"
	"passed/internal/password"
)

func main() {
	if len(os.Args) < 2 {
		printHelp()
		os.Exit(0)
	}

	if os.Args[1] == "generate" {
		if err := generateMnemonic(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	// otherwise treat as domain derivation
	if err := derivePassword(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func printHelp() {
	fmt.Fprintln(os.Stderr, `usage: passed generate
       passed <domain> [counter]

environment: PASSED_MNEMONIC`)
}

func generateMnemonic() error {
	phrase, err := mnemonic.Generate()
	if err != nil {
		return err
	}
	fmt.Println(phrase)
	return nil
}

func derivePassword(args []string) error {
	if len(args) < 1 || len(args) > 2 {
		printHelp()
		os.Exit(1)
	}

	domain := args[0]
	counter := 0

	if len(args) == 2 {
		var err error
		counter, err = strconv.Atoi(args[1])
		if err != nil {
			return fmt.Errorf("invalid counter: %s", args[1])
		}
		if counter < 0 {
			return fmt.Errorf("counter must be >= 0")
		}
	}

	// get mnemonic from env, stdin pipe, or interactive prompt
	phrase := os.Getenv("PASSED_MNEMONIC")
	if phrase == "" {
		// check if stdin is a pipe/file or a terminal
		stat, err := os.Stdin.Stat()
		if err != nil {
			return fmt.Errorf("failed to stat stdin: %w", err)
		}

		if (stat.Mode() & os.ModeCharDevice) == 0 {
			// stdin is a pipe/file. read from it silently
			scanner := bufio.NewScanner(os.Stdin)
			if scanner.Scan() {
				phrase = scanner.Text()
			}
			if err := scanner.Err(); err != nil {
				return fmt.Errorf("failed to read from stdin: %w", err)
			}
		} else {
			// stdin is a terminal. use interactive password prompt
			fmt.Fprint(os.Stderr, "mnemonic: ")
			phraseBytes, err := term.ReadPassword(int(syscall.Stdin))
			if err != nil {
				return err
			}
			fmt.Fprintln(os.Stderr)
			phrase = string(phraseBytes)
		}
	}

	phrase = strings.TrimSpace(phrase)
	if phrase == "" {
		return fmt.Errorf("empty mnemonic")
	}

	if err := mnemonic.Validate(phrase); err != nil {
		return err
	}

	// derive password
	derived := crypto.DeriveKey(phrase, domain, counter)
	passwd := password.Generate(derived)

	fmt.Println(passwd)
	return nil
}
