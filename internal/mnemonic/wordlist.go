package mnemonic

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
)

const (
	ExpectedWordlistSize = 16384
	MnemonicWordCount    = 16
)

var (
	wordlist    []string
	wordlistSet map[string]bool
)

// Parses and validates the embedded wordlist
func init() {
	lines := strings.Split(strings.TrimSpace(embeddedWordlistRaw), "\n")
	wordlist = make([]string, 0, len(lines))

	for _, line := range lines {
		word := strings.TrimSpace(strings.ToLower(line))
		if word != "" {
			wordlist = append(wordlist, word)
		}
	}

	if len(wordlist) != ExpectedWordlistSize {
		panic(fmt.Sprintf("wordlist must have %d words, got %d",
			ExpectedWordlistSize, len(wordlist)))
	}

	wordlistSet = make(map[string]bool, len(wordlist))
	for _, word := range wordlist {
		if wordlistSet[word] {
			panic(fmt.Sprintf("duplicate word in wordlist: %s", word))
		}
		wordlistSet[word] = true
	}
}

// Generate creates a new 16-word mnemonic using cryptographically secure random
func Generate() (string, error) {
	words := make([]string, MnemonicWordCount)

	for i := 0; i < MnemonicWordCount; i++ {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(wordlist))))
		if err != nil {
			return "", fmt.Errorf("random generation failed: %w", err)
		}
		words[i] = wordlist[idx.Int64()]
	}

	return strings.Join(words, " "), nil
}

// Validate checks if a mnemonic phrase is valid
func Validate(phrase string) error {
	words := strings.Fields(strings.ToLower(phrase))

	if len(words) != MnemonicWordCount {
		return fmt.Errorf("mnemonic must be exactly %d words, got %d",
			MnemonicWordCount, len(words))
	}

	var invalid []string
	for _, word := range words {
		if !wordlistSet[word] {
			invalid = append(invalid, word)
		}
	}

	if len(invalid) > 0 {
		return fmt.Errorf("invalid words not in wordlist: %s",
			strings.Join(invalid, ", "))
	}

	return nil
}
