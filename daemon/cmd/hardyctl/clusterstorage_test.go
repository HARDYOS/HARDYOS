package main

import (
	"strings"
	"testing"
)

func TestClusterStorageConfirmation(t *testing.T) {
	if err := confirmTyped(strings.NewReader("c1\n"), "x", "c1"); err != nil {
		t.Fatal(err)
	}
	for _, in := range []string{"", "c2\n", "c1x\n"} {
		if err := confirmTyped(strings.NewReader(in), "x", "c1"); err == nil {
			t.Errorf("%q confirmed", in)
		}
	}
	if err := clusterStorage("/nonexistent", []string{"repin"}, strings.NewReader("")); err == nil {
		t.Fatal("usage not enforced")
	}
	if err := clusterStorage("/nonexistent", []string{"drop", "c1"}, strings.NewReader("c1\n")); err == nil {
		t.Fatal("unknown verb accepted")
	}
}
