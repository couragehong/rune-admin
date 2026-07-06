// Package rbac implements group-scoped access control for vault memory.
//
// Model (three layers, see docs/rune-RBAC section 7):
//   - Policy source: SQLite tables groups (tree via parent_id), members,
//     grants ((member × group) -> role). Grants are materialized (closure):
//     inviting into a group copies rows to every descendant, so runtime
//     evaluation never walks the tree.
//   - Compiled scope: ScopeOf(member, verb) is a single projection over
//     grants. No cache in the MVP — the query is microseconds at this scale.
//   - Data-plane predicate: a record carries one group id tag; it is visible
//     iff tag ∈ ScopeOf(member, read). Records without a tag are public
//     (legacy fail-open).
//
// All mutations flow through Plan/Apply so the admin surface can preview
// row diffs before committing (R1/R2 dialogs).
package rbac

import (
	"database/sql"
	"errors"
	"fmt"
	"sort"

	"github.com/google/uuid"
	_ "modernc.org/sqlite" // pure-Go sqlite driver
)

// Verb is a bitmask of actions a role permits.
type Verb uint8

// Verb bits. Manage covers group/member administration.
const (
	VerbRead Verb = 1 << iota
	VerbWrite
	VerbDelete
	VerbManage
)

// RoleVerbs maps the four built-in roles to their verb bitmasks.
// The lattice is linear: read < write < edit < admin.
var RoleVerbs = map[string]Verb{
	"read":  VerbRead,
	"write": VerbRead | VerbWrite,
	"edit":  VerbRead | VerbWrite | VerbDelete,
	"admin": VerbRead | VerbWrite | VerbDelete | VerbManage,
}

// ValidRole reports whether name is one of the built-in roles.
func ValidRole(name string) bool { _, ok := RoleVerbs[name]; return ok }

// Group is one node of the access-group tree.
type Group struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	ParentID string `json:"parent_id,omitempty"`
}

// Member links a vault token user to the rbac tables. ID equals the token
// username. DefaultGroup is the capture target used when a request does not
// specify one (MVP: requests never do).
type Member struct {
	ID           string `json:"id"`
	DefaultGroup string `json:"default_group,omitempty"`
}

// Grant is one (member × group) -> role row.
type Grant struct {
	MemberID  string `json:"member_id"`
	GroupID   string `json:"group_id"`
	GroupName string `json:"group_name,omitempty"`
	Role      string `json:"role"`
}

// Change is one row-level mutation inside a Plan.
type Change struct {
	Op        string  `json:"op"` // "add" | "update" | "remove"
	MemberID  string  `json:"member_id"`
	GroupID   string  `json:"group_id"`
	GroupName string  `json:"group_name"`
	Role      string  `json:"role,omitempty"`
	PrevRole  *string `json:"prev_role,omitempty"`
}

// Plan is a previewable batch of grant changes. Reason names the rule that
// produced it (audit trail).
type Plan struct {
	Reason  string   `json:"reason"`
	Changes []Change `json:"changes"`
}

// Store owns the rbac SQLite database. Safe for concurrent use (database/sql
// serializes; sqlite runs single-writer).
type Store struct{ db *sql.DB }

// Open opens (creating if needed) the rbac database at path and ensures the
// schema exists.
func Open(path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("rbac: db path is empty")
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("rbac: open %s: %w", path, err)
	}
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("rbac: ensure schema: %w", err)
	}
	return &Store{db: db}, nil
}

const schema = `
CREATE TABLE IF NOT EXISTS groups (
  id        TEXT PRIMARY KEY,
  name      TEXT NOT NULL UNIQUE,
  parent_id TEXT REFERENCES groups(id)
);
CREATE TABLE IF NOT EXISTS members (
  id            TEXT PRIMARY KEY,
  default_group TEXT REFERENCES groups(id)
);
CREATE TABLE IF NOT EXISTS grants (
  member_id TEXT NOT NULL,
  group_id  TEXT NOT NULL REFERENCES groups(id),
  role      TEXT NOT NULL,
  PRIMARY KEY (member_id, group_id)
);
CREATE INDEX IF NOT EXISTS idx_grants_group ON grants(group_id);
`

// Close releases the underlying database handle.
func (s *Store) Close() error { return s.db.Close() }

// ── groups ──────────────────────────────────────────────────────────

// CreateGroup inserts a new group under parentID (empty = root) and, when
// copyParent is true (rule R1), returns the applied copy plan; the returned
// plan is empty when copyParent is false or the parent has no members.
func (s *Store) CreateGroup(name, parentID string, copyParent bool) (Group, Plan, error) {
	g := Group{ID: uuid.NewString(), Name: name, ParentID: parentID}
	plan := Plan{Reason: fmt.Sprintf("R1: create-group %s", name)}
	if parentID != "" {
		if _, err := s.GroupByID(parentID); err != nil {
			return Group{}, plan, err
		}
		if copyParent {
			rows, err := s.db.Query(`SELECT member_id, role FROM grants WHERE group_id = ?`, parentID)
			if err != nil {
				return Group{}, plan, err
			}
			defer rows.Close()
			for rows.Next() {
				var m, r string
				if err := rows.Scan(&m, &r); err != nil {
					return Group{}, plan, err
				}
				plan.Changes = append(plan.Changes, Change{Op: "add", MemberID: m, GroupID: g.ID, GroupName: name, Role: r})
			}
			if err := rows.Err(); err != nil {
				return Group{}, plan, err
			}
		}
	}
	tx, err := s.db.Begin()
	if err != nil {
		return Group{}, plan, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`INSERT INTO groups (id, name, parent_id) VALUES (?, ?, NULLIF(?, ''))`,
		g.ID, g.Name, g.ParentID); err != nil {
		return Group{}, plan, fmt.Errorf("rbac: create group %q: %w", name, err)
	}
	if err := applyTx(tx, plan); err != nil {
		return Group{}, plan, err
	}
	if err := tx.Commit(); err != nil {
		return Group{}, plan, err
	}
	return g, plan, nil
}

// GroupByID returns the group with the given id.
func (s *Store) GroupByID(id string) (Group, error) {
	var g Group
	var parent sql.NullString
	err := s.db.QueryRow(`SELECT id, name, parent_id FROM groups WHERE id = ?`, id).
		Scan(&g.ID, &g.Name, &parent)
	if errors.Is(err, sql.ErrNoRows) {
		return Group{}, fmt.Errorf("rbac: group %q not found", id)
	}
	if err != nil {
		return Group{}, err
	}
	g.ParentID = parent.String
	return g, nil
}

// ResolveGroup accepts a group name or id and returns the group.
func (s *Store) ResolveGroup(nameOrID string) (Group, error) {
	var g Group
	var parent sql.NullString
	err := s.db.QueryRow(`SELECT id, name, parent_id FROM groups WHERE id = ? OR name = ?`,
		nameOrID, nameOrID).Scan(&g.ID, &g.Name, &parent)
	if errors.Is(err, sql.ErrNoRows) {
		return Group{}, fmt.Errorf("rbac: group %q not found", nameOrID)
	}
	if err != nil {
		return Group{}, err
	}
	g.ParentID = parent.String
	return g, nil
}

// ListGroups returns all groups ordered by name.
func (s *Store) ListGroups() ([]Group, error) {
	rows, err := s.db.Query(`SELECT id, name, parent_id FROM groups ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Group
	for rows.Next() {
		var g Group
		var parent sql.NullString
		if err := rows.Scan(&g.ID, &g.Name, &parent); err != nil {
			return nil, err
		}
		g.ParentID = parent.String
		out = append(out, g)
	}
	return out, rows.Err()
}

// Descendants returns the ids of every group strictly below groupID.
func (s *Store) Descendants(groupID string) ([]string, error) {
	rows, err := s.db.Query(`
	  WITH RECURSIVE sub(id) AS (
	    SELECT id FROM groups WHERE parent_id = ?
	    UNION ALL
	    SELECT g.id FROM groups g JOIN sub ON g.parent_id = sub.id
	  ) SELECT id FROM sub`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// ── members ─────────────────────────────────────────────────────────

// EnsureMember upserts a member row. defaultGroupID may be empty to leave
// the capture target unset.
func (s *Store) EnsureMember(id, defaultGroupID string) error {
	_, err := s.db.Exec(`
	  INSERT INTO members (id, default_group) VALUES (?, NULLIF(?, ''))
	  ON CONFLICT(id) DO UPDATE SET default_group = NULLIF(excluded.default_group, '')`,
		id, defaultGroupID)
	return err
}

// ListMembers returns all members ordered by id.
func (s *Store) ListMembers() ([]Member, error) {
	rows, err := s.db.Query(`SELECT id, default_group FROM members ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Member
	for rows.Next() {
		var m Member
		var dg sql.NullString
		if err := rows.Scan(&m.ID, &dg); err != nil {
			return nil, err
		}
		m.DefaultGroup = dg.String
		out = append(out, m)
	}
	return out, rows.Err()
}

// DefaultGroup returns the member's capture target group id, or "" when the
// member is unknown or has no default group.
func (s *Store) DefaultGroup(memberID string) (string, error) {
	var dg sql.NullString
	err := s.db.QueryRow(`SELECT default_group FROM members WHERE id = ?`, memberID).Scan(&dg)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return dg.String, nil
}

// ── plans (R1/R2 + invite) ──────────────────────────────────────────

// PlanInvite returns the materialized-closure plan for granting role on
// group and every descendant (the spec's downward copy). Existing rows
// surface as "update" changes with their previous role, so overlapping
// invites are visible in the preview instead of silently overwritten.
func (s *Store) PlanInvite(memberID, groupID, role string) (Plan, error) {
	if !ValidRole(role) {
		return Plan{}, fmt.Errorf("rbac: unknown role %q (want read|write|edit|admin)", role)
	}
	root, err := s.GroupByID(groupID)
	if err != nil {
		return Plan{}, err
	}
	desc, err := s.Descendants(groupID)
	if err != nil {
		return Plan{}, err
	}
	plan := Plan{Reason: fmt.Sprintf("invite %s -> %s (%s)", memberID, root.Name, role)}
	for _, gid := range append([]string{groupID}, desc...) {
		g, err := s.GroupByID(gid)
		if err != nil {
			return Plan{}, err
		}
		var prev sql.NullString
		err = s.db.QueryRow(`SELECT role FROM grants WHERE member_id = ? AND group_id = ?`,
			memberID, gid).Scan(&prev)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return Plan{}, err
		}
		ch := Change{Op: "add", MemberID: memberID, GroupID: gid, GroupName: g.Name, Role: role}
		if prev.Valid {
			p := prev.String
			ch.Op, ch.PrevRole = "update", &p
		}
		plan.Changes = append(plan.Changes, ch)
	}
	return plan, nil
}

// PlanRemove returns the plan removing the member from group and, when
// cascade is true (rule R2 "remove below as well"), from every descendant.
func (s *Store) PlanRemove(memberID, groupID string, cascade bool) (Plan, error) {
	root, err := s.GroupByID(groupID)
	if err != nil {
		return Plan{}, err
	}
	targets := []string{groupID}
	if cascade {
		desc, err := s.Descendants(groupID)
		if err != nil {
			return Plan{}, err
		}
		targets = append(targets, desc...)
	}
	plan := Plan{Reason: fmt.Sprintf("R2: remove %s from %s (cascade=%v)", memberID, root.Name, cascade)}
	for _, gid := range targets {
		var prev string
		err := s.db.QueryRow(`SELECT role FROM grants WHERE member_id = ? AND group_id = ?`,
			memberID, gid).Scan(&prev)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return Plan{}, err
		}
		g, err := s.GroupByID(gid)
		if err != nil {
			return Plan{}, err
		}
		p := prev
		plan.Changes = append(plan.Changes, Change{
			Op: "remove", MemberID: memberID, GroupID: gid, GroupName: g.Name, PrevRole: &p,
		})
	}
	return plan, nil
}

// Apply commits a plan in one transaction. Change entries may exclude rows
// the admin rejected in the preview (e.g. the sticky-trap row on re-invite).
func (s *Store) Apply(plan Plan) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := applyTx(tx, plan); err != nil {
		return err
	}
	return tx.Commit()
}

func applyTx(tx *sql.Tx, plan Plan) error {
	for _, ch := range plan.Changes {
		switch ch.Op {
		case "add", "update":
			if !ValidRole(ch.Role) {
				return fmt.Errorf("rbac: change on %s has unknown role %q", ch.GroupName, ch.Role)
			}
			if _, err := tx.Exec(`
			  INSERT INTO grants (member_id, group_id, role) VALUES (?, ?, ?)
			  ON CONFLICT(member_id, group_id) DO UPDATE SET role = excluded.role`,
				ch.MemberID, ch.GroupID, ch.Role); err != nil {
				return err
			}
		case "remove":
			if _, err := tx.Exec(`DELETE FROM grants WHERE member_id = ? AND group_id = ?`,
				ch.MemberID, ch.GroupID); err != nil {
				return err
			}
		default:
			return fmt.Errorf("rbac: unknown change op %q", ch.Op)
		}
	}
	return nil
}

// ── grants & scope ──────────────────────────────────────────────────

// Grants lists grant rows, optionally filtered by member and/or group id.
func (s *Store) Grants(memberID, groupID string) ([]Grant, error) {
	rows, err := s.db.Query(`
	  SELECT gr.member_id, gr.group_id, g.name, gr.role
	  FROM grants gr JOIN groups g ON g.id = gr.group_id
	  WHERE (? = '' OR gr.member_id = ?) AND (? = '' OR gr.group_id = ?)
	  ORDER BY gr.member_id, g.name`,
		memberID, memberID, groupID, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Grant
	for rows.Next() {
		var g Grant
		if err := rows.Scan(&g.MemberID, &g.GroupID, &g.GroupName, &g.Role); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// ScopeOf compiles the member's allowed group-id set for a verb. This is the
// layer-2 projection: one query over grants, no tree walk (grants hold the
// materialized closure).
func (s *Store) ScopeOf(memberID string, verb Verb) (map[string]struct{}, error) {
	rows, err := s.db.Query(`SELECT group_id, role FROM grants WHERE member_id = ?`, memberID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	scope := make(map[string]struct{})
	for rows.Next() {
		var gid, role string
		if err := rows.Scan(&gid, &role); err != nil {
			return nil, err
		}
		if RoleVerbs[role]&verb != 0 {
			scope[gid] = struct{}{}
		}
	}
	return scope, rows.Err()
}

// Allowed reports whether the member may perform verb on the group.
func (s *Store) Allowed(memberID, groupID string, verb Verb) (bool, error) {
	scope, err := s.ScopeOf(memberID, verb)
	if err != nil {
		return false, err
	}
	_, ok := scope[groupID]
	return ok, nil
}

// ScopeNames returns the sorted group names in the member's scope for a verb
// (admin/status surfaces).
func (s *Store) ScopeNames(memberID string, verb Verb) ([]string, error) {
	scope, err := s.ScopeOf(memberID, verb)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(scope))
	for gid := range scope {
		g, err := s.GroupByID(gid)
		if err != nil {
			return nil, err
		}
		names = append(names, g.Name)
	}
	sort.Strings(names)
	return names, nil
}
