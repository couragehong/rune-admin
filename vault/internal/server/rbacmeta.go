package server

import "encoding/json"

// rbacGroupKey and rbacMemberKey are the metadata fields the vault stamps
// into a record's plaintext metadata JSON before sealing (Insert) and reads
// back after opening (Search). They live inside the sealed envelope, so the
// blind index never sees them; clients that unmarshal the record simply
// ignore the extra keys.
const (
	rbacGroupKey  = "_rbac_group"
	rbacMemberKey = "_rbac_member"
)

// stampRBACMeta injects the authenticated author and target group into the
// metadata JSON object. Empty or non-object metadata is returned unchanged —
// such records stay legacy-public rather than failing the capture.
func stampRBACMeta(meta, groupID, memberID string) string {
	if meta == "" {
		return meta
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(meta), &obj); err != nil || obj == nil {
		return meta
	}
	obj[rbacGroupKey] = groupID
	obj[rbacMemberKey] = memberID
	out, err := json.Marshal(obj)
	if err != nil {
		return meta
	}
	return string(out)
}

// rbacGroupOf extracts the stamped group id from opened metadata JSON.
// Returns "" for legacy records without a stamp (treated as public).
func rbacGroupOf(meta string) string {
	if meta == "" {
		return ""
	}
	var obj struct {
		Group string `json:"_rbac_group"`
	}
	if err := json.Unmarshal([]byte(meta), &obj); err != nil {
		return ""
	}
	return obj.Group
}
