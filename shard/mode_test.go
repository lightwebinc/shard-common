package shard

import (
	"testing"
)

func TestSourceModeString(t *testing.T) {
	t.Parallel()
	if got := SourceModeASM.String(); got != "asm" {
		t.Errorf("SourceModeASM.String() = %q, want %q", got, "asm")
	}
	if got := SourceModeSSM.String(); got != "ssm" {
		t.Errorf("SourceModeSSM.String() = %q, want %q", got, "ssm")
	}
}

func TestParseSourceMode(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want SourceMode
		err  bool
	}{
		{"asm", SourceModeASM, false},
		{"ASM", SourceModeASM, false},
		{"ssm", SourceModeSSM, false},
		{"SSM", SourceModeSSM, false},
		{"", 0, true},
		{"any", 0, true},
	}
	for _, tc := range cases {
		got, err := ParseSourceMode(tc.in)
		if (err != nil) != tc.err {
			t.Errorf("ParseSourceMode(%q) err = %v, want err? %v", tc.in, err, tc.err)
			continue
		}
		if !tc.err && got != tc.want {
			t.Errorf("ParseSourceMode(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestScopeString(t *testing.T) {
	t.Parallel()
	if got := ScopeSite.String(); got != "site" {
		t.Errorf("ScopeSite.String() = %q, want %q", got, "site")
	}
	if got := ScopeGlobal.String(); got != "global" {
		t.Errorf("ScopeGlobal.String() = %q, want %q", got, "global")
	}
}

func TestParseScope(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want Scope
		err  bool
	}{
		{"site", ScopeSite, false},
		{"SITE", ScopeSite, false},
		{"global", ScopeGlobal, false},
		{"GLOBAL", ScopeGlobal, false},
		{"", 0, true},
		{"org", 0, true},
	}
	for _, tc := range cases {
		got, err := ParseScope(tc.in)
		if (err != nil) != tc.err {
			t.Errorf("ParseScope(%q) err = %v, want err? %v", tc.in, err, tc.err)
			continue
		}
		if !tc.err && got != tc.want {
			t.Errorf("ParseScope(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestPrefix(t *testing.T) {
	t.Parallel()
	cases := []struct {
		mode   SourceMode
		scope  Scope
		want   uint16
		hasErr bool
	}{
		{SourceModeASM, ScopeSite, 0xFF05, false},
		{SourceModeSSM, ScopeSite, 0xFF35, false},
		{SourceModeSSM, ScopeGlobal, 0xFF3E, false},
		{SourceModeASM, ScopeGlobal, 0, true}, // RFC 8815 deprecation
	}
	for _, tc := range cases {
		got, err := Prefix(tc.mode, tc.scope)
		if (err != nil) != tc.hasErr {
			t.Errorf("Prefix(%s, %s) err = %v, want err? %v", tc.mode, tc.scope, err, tc.hasErr)
			continue
		}
		if !tc.hasErr && got != tc.want {
			t.Errorf("Prefix(%s, %s) = %#x, want %#x", tc.mode, tc.scope, got, tc.want)
		}
	}
}

func TestPrefix_RFC8815_DeprecationMessageMentionsRFC(t *testing.T) {
	t.Parallel()
	// The error for (ASM, global) MUST mention RFC 8815 so operators
	// who hit it understand why ASM global is rejected.
	_, err := Prefix(SourceModeASM, ScopeGlobal)
	if err == nil {
		t.Fatal("Prefix(ASM, global) returned nil error, want RFC 8815 deprecation error")
	}
	if !contains(err.Error(), "RFC 8815") {
		t.Errorf("Prefix(ASM, global) error = %q, want substring %q", err.Error(), "RFC 8815")
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
