package server

import (
	"encoding/json"
	"testing"
)

func TestStampAndExtractRBACMeta(t *testing.T) {
	in := `{"title":"DB split","tags":["x"]}`
	out := stampRBACMeta(in, "g-be", "minsu")

	if got := rbacGroupOf(out); got != "g-be" {
		t.Fatalf("group: want g-be, got %q", got)
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(out), &obj); err != nil {
		t.Fatalf("stamped metadata is not JSON: %v", err)
	}
	if obj["title"] != "DB split" {
		t.Errorf("original fields must survive the stamp, got %v", obj["title"])
	}
	if obj[rbacMemberKey] != "minsu" {
		t.Errorf("member stamp: want minsu, got %v", obj[rbacMemberKey])
	}
}

func TestStampRBACMetaLegacyTolerance(t *testing.T) {
	for _, in := range []string{"", "not-json", `[1,2]`} {
		if out := stampRBACMeta(in, "g", "m"); out != in {
			t.Errorf("stamp(%q) must be a no-op, got %q", in, out)
		}
	}
	if got := rbacGroupOf(`{"title":"legacy"}`); got != "" {
		t.Errorf("legacy record group: want empty, got %q", got)
	}
	if got := rbacGroupOf("not-json"); got != "" {
		t.Errorf("non-JSON group: want empty, got %q", got)
	}
}
