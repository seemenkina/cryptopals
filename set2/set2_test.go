package set2

import (
	"bytes"
	"testing"
)

func TestPKCS7Pad(t *testing.T) {
	input := []byte("YELLOW SUBMARINE")
	expected := []byte("YELLOW SUBMARINE\x04\x04\x04\x04")
	lenBlock := 20
	actual, err := AddPKCS7Pad(input, lenBlock)
	if err != nil {
		t.Errorf("function return %s", err)
	}

	if !bytes.Equal(actual, expected) {
		t.Errorf("Expected %x, got %x", expected, actual)
	}
}

func TestPKCS7PadGran(t *testing.T) {
	input := []byte("YELLOW SUBMARINE")
	expected := []byte("YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10")
	lenBlock := 16
	actual, err := AddPKCS7Pad(input, lenBlock)
	if err != nil {
		t.Errorf("function return %s", err)
	}

	if !bytes.Equal(actual, expected) {
		t.Errorf("Expected %x, got %x", expected, actual)
	}
}

func TestPKCS7PadBig(t *testing.T) {
	input := []byte("YELLOW SUBMARINE YELLOW")
	expected := []byte("YELLOW SUBMARINE YELLOW\x09\x09\x09\x09\x09\x09\x09\x09\x09")
	lenBlock := 16
	actual, err := AddPKCS7Pad(input, lenBlock)
	if err != nil {
		t.Errorf("function return %s", err)
	}

	if !bytes.Equal(actual, expected) {
		t.Errorf("Expected %x, got %x", expected, actual)
	}
}

func TestRemovePKCS7PadBig(t *testing.T) {
	input := []byte("YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10")
	expected := []byte("YELLOW SUBMARINE")
	lenBlock := 16
	actual, err := RemovePKCS7Pad(input, lenBlock)
	if err != nil {
		t.Errorf("function return %s", err)
	}

	if !bytes.Equal(actual, expected) {
		t.Errorf("Expected %x, got %x", expected, actual)
	}
}

func TestRemovePKCS7PadFull(t *testing.T) {
	input := []byte("YELLOW SUBMARINE YELLOW\x09\x09\x09\x09\x09\x09\x09\x09\x09")
	expected := []byte("YELLOW SUBMARINE YELLOW")
	lenBlock := 16
	actual, err := RemovePKCS7Pad(input, lenBlock)
	if err != nil {
		t.Errorf("function return %s", err)
	}

	if !bytes.Equal(actual, expected) {
		t.Errorf("Expected %x, got %x", expected, actual)
	}
}

func TestRemovePKCS7Pad(t *testing.T) {
	input := []byte("YELLOW SUBMARINE\x04\x04\x04\x04")
	expected := []byte("YELLOW SUBMARINE")
	lenBlock := 20
	actual, err := RemovePKCS7Pad(input, lenBlock)
	if err != nil {
		t.Errorf("function return %s", err)
	}

	if !bytes.Equal(actual, expected) {
		t.Errorf("Expected %x, got %x", expected, actual)
	}
}
