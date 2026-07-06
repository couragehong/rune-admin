package rbac

import (
	"path/filepath"
	"testing"
)

// openTestStore returns a Store backed by a throwaway on-disk database.
func openTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "rbac.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// mustApply plans nothing on its own — it applies the given plan and fails
// the test on error.
func mustApply(t *testing.T, s *Store, p Plan) {
	t.Helper()
	if err := s.Apply(p); err != nil {
		t.Fatalf("apply %q: %v", p.Reason, err)
	}
}

func mustInvite(t *testing.T, s *Store, member, groupID, role string) Plan {
	t.Helper()
	p, err := s.PlanInvite(member, groupID, role)
	if err != nil {
		t.Fatalf("plan invite: %v", err)
	}
	mustApply(t, s, p)
	return p
}

// TestAcmeScenario replays the "two weeks at Acme" walkthrough from the
// design doc (docs/rune-RBAC, section 7 §8) scene by scene.
func TestAcmeScenario(t *testing.T) {
	s := openTestStore(t)

	// Scene 0 — group tree.
	acme, _, err := s.CreateGroup("acme", "", false)
	if err != nil {
		t.Fatalf("create acme: %v", err)
	}
	dev, _, err := s.CreateGroup("dev", acme.ID, false)
	if err != nil {
		t.Fatalf("create dev: %v", err)
	}
	be, _, err := s.CreateGroup("be", dev.ID, false)
	if err != nil {
		t.Fatalf("create be: %v", err)
	}
	fe, _, err := s.CreateGroup("fe", dev.ID, false)
	if err != nil {
		t.Fatalf("create fe: %v", err)
	}

	// Scene 1 — invites. Jiyeon on dev copies down to be and fe.
	p := mustInvite(t, s, "jiyeon", dev.ID, "admin")
	if len(p.Changes) != 3 {
		t.Fatalf("invite jiyeon: want 3 changes (dev+be+fe), got %d", len(p.Changes))
	}
	mustInvite(t, s, "minsu", be.ID, "write")
	mustInvite(t, s, "hana", fe.ID, "write")
	mustInvite(t, s, "jun", be.ID, "read")
	if rows, _ := s.Grants("", ""); len(rows) != 6 {
		t.Fatalf("grants: want 6 rows, got %d", len(rows))
	}

	// Scene 3 — same record, three scopes. Tag = be.
	for _, tc := range []struct {
		member string
		want   bool
	}{{"minsu", true}, {"hana", false}, {"jiyeon", true}} {
		ok, err := s.Allowed(tc.member, be.ID, VerbRead)
		if err != nil {
			t.Fatalf("allowed(%s): %v", tc.member, err)
		}
		if ok != tc.want {
			t.Errorf("read be as %s: want %v, got %v", tc.member, tc.want, ok)
		}
	}

	// Scene 4 — jun (read) cannot write; promoting fixes it.
	if ok, _ := s.Allowed("jun", be.ID, VerbWrite); ok {
		t.Error("jun should not have write on be yet")
	}
	mustApply(t, s, Plan{Reason: "promote jun", Changes: []Change{
		{Op: "update", MemberID: "jun", GroupID: be.ID, GroupName: "be", Role: "write"},
	}})
	if ok, _ := s.Allowed("jun", be.ID, VerbWrite); !ok {
		t.Error("jun should have write on be after promotion")
	}

	// Scene 5 — new subgroup pf copies parent members (R1).
	pf, copyPlan, err := s.CreateGroup("pf", dev.ID, true)
	if err != nil {
		t.Fatalf("create pf: %v", err)
	}
	if len(copyPlan.Changes) != 1 || copyPlan.Changes[0].MemberID != "jiyeon" {
		t.Fatalf("R1 copy: want jiyeon only, got %+v", copyPlan.Changes)
	}
	mustInvite(t, s, "minsu", pf.ID, "write")

	// Scene 6 — secret task force created without the R1 copy.
	tf, copyPlan, err := s.CreateGroup("s", dev.ID, false)
	if err != nil {
		t.Fatalf("create s: %v", err)
	}
	if len(copyPlan.Changes) != 0 {
		t.Fatalf("R1 skip: want empty plan, got %+v", copyPlan.Changes)
	}
	mustInvite(t, s, "hana", tf.ID, "edit")
	if ok, _ := s.Allowed("jiyeon", tf.ID, VerbRead); ok {
		t.Error("jiyeon (dev admin) must not see the secret group s")
	}

	// Scene 7 — minsu leaves; R2 shows exactly his rows.
	rm, err := s.PlanRemove("minsu", be.ID, false)
	if err != nil {
		t.Fatalf("plan remove be: %v", err)
	}
	rm2, err := s.PlanRemove("minsu", pf.ID, false)
	if err != nil {
		t.Fatalf("plan remove pf: %v", err)
	}
	if len(rm.Changes)+len(rm2.Changes) != 2 {
		t.Fatalf("R2: want 2 removals, got %d", len(rm.Changes)+len(rm2.Changes))
	}
	mustApply(t, s, rm)
	mustApply(t, s, rm2)
	if scope, _ := s.ScopeOf("minsu", VerbRead); len(scope) != 0 {
		t.Errorf("minsu scope after removal: want empty, got %v", scope)
	}

	// Scene 8 — re-inviting jiyeon to dev surfaces the sticky-trap row for s
	// in the preview; the admin strips it before applying.
	full, err := s.PlanRemove("jiyeon", dev.ID, true)
	if err != nil {
		t.Fatalf("plan remove jiyeon: %v", err)
	}
	mustApply(t, s, full)
	reinvite, err := s.PlanInvite("jiyeon", dev.ID, "admin")
	if err != nil {
		t.Fatalf("plan reinvite: %v", err)
	}
	var sawTrap bool
	kept := Plan{Reason: reinvite.Reason}
	for _, ch := range reinvite.Changes {
		if ch.GroupID == tf.ID {
			sawTrap = true
			continue // admin rejects the secret-group row in the preview
		}
		kept.Changes = append(kept.Changes, ch)
	}
	if !sawTrap {
		t.Fatal("re-invite preview must include the secret group row (sticky trap)")
	}
	mustApply(t, s, kept)
	if ok, _ := s.Allowed("jiyeon", tf.ID, VerbRead); ok {
		t.Error("jiyeon must still not see s after trimmed re-invite")
	}
	if ok, _ := s.Allowed("jiyeon", pf.ID, VerbRead); !ok {
		t.Error("jiyeon should see pf again after re-invite")
	}
}

// TestInviteOverlapIsVisible pins the overlapping-invite behaviour: a second
// invite touching existing rows must surface them as updates with the
// previous role, never as silent adds.
func TestInviteOverlapIsVisible(t *testing.T) {
	s := openTestStore(t)
	root, _, _ := s.CreateGroup("root", "", false)
	child, _, err := s.CreateGroup("child", root.ID, false)
	if err != nil {
		t.Fatalf("create child: %v", err)
	}
	mustInvite(t, s, "kim", child.ID, "write")

	p, err := s.PlanInvite("kim", root.ID, "edit")
	if err != nil {
		t.Fatalf("plan overlapping invite: %v", err)
	}
	var update *Change
	for i := range p.Changes {
		if p.Changes[i].GroupID == child.ID {
			update = &p.Changes[i]
		}
	}
	if update == nil || update.Op != "update" || update.PrevRole == nil || *update.PrevRole != "write" {
		t.Fatalf("overlap on child must be an update carrying prev role, got %+v", update)
	}
}

// TestScopeProjection covers the verb lattice through ScopeOf.
func TestScopeProjection(t *testing.T) {
	s := openTestStore(t)
	g, _, _ := s.CreateGroup("g", "", false)
	mustInvite(t, s, "u", g.ID, "read")

	if ok, _ := s.Allowed("u", g.ID, VerbRead); !ok {
		t.Error("read role must grant VerbRead")
	}
	for _, v := range []Verb{VerbWrite, VerbDelete, VerbManage} {
		if ok, _ := s.Allowed("u", g.ID, v); ok {
			t.Errorf("read role must not grant verb %b", v)
		}
	}
	if scope, _ := s.ScopeOf("stranger", VerbRead); len(scope) != 0 {
		t.Errorf("unknown member scope must be empty, got %v", scope)
	}
}
