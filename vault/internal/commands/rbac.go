package commands

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
)

// newRBACCmd groups the rbac admin surface: access groups, member defaults,
// hierarchical invites (materialized closure) and scope inspection. All
// subcommands talk to the daemon over the admin UDS.
func newRBACCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rbac",
		Short: "Manage group-scoped access control (groups, members, grants)",
	}
	cmd.AddCommand(
		newRBACGroupCreateCmd(),
		newRBACGroupListCmd(),
		newRBACMemberAddCmd(),
		newRBACMemberListCmd(),
		newRBACInviteCmd(),
		newRBACRemoveCmd(),
		newRBACGrantsCmd(),
		newRBACScopeCmd(),
	)
	return cmd
}

func printJSON(v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}

func newRBACGroupCreateCmd() *cobra.Command {
	var parent string
	var copyParent bool
	cmd := &cobra.Command{
		Use:   "group-create <name>",
		Short: "Create an access group (R1: --copy-parent copies parent members)",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			ac, err := resolveAdminClient()
			if err != nil {
				return err
			}
			var out map[string]any
			if err := ac.Do("POST", "/rbac/groups", map[string]any{
				"name": args[0], "parent": parent, "copy_parent": copyParent,
			}, &out); err != nil {
				return err
			}
			return printJSON(out)
		},
	}
	cmd.Flags().StringVar(&parent, "parent", "", "Parent group name or id (empty = root)")
	cmd.Flags().BoolVar(&copyParent, "copy-parent", false, "Copy parent members into the new group (R1)")
	return cmd
}

func newRBACGroupListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "group-list",
		Short: "List access groups",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			ac, err := resolveAdminClient()
			if err != nil {
				return err
			}
			var out map[string]any
			if err := ac.Do("GET", "/rbac/groups", nil, &out); err != nil {
				return err
			}
			return printJSON(out)
		},
	}
}

func newRBACMemberAddCmd() *cobra.Command {
	var defaultGroup string
	cmd := &cobra.Command{
		Use:   "member-add <user>",
		Short: "Register a token user with rbac and set the capture target group",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			ac, err := resolveAdminClient()
			if err != nil {
				return err
			}
			var out map[string]any
			if err := ac.Do("POST", "/rbac/members", map[string]any{
				"id": args[0], "default_group": defaultGroup,
			}, &out); err != nil {
				return err
			}
			return printJSON(out)
		},
	}
	cmd.Flags().StringVar(&defaultGroup, "default-group", "", "Capture target group name or id")
	return cmd
}

func newRBACMemberListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "member-list",
		Short: "List rbac members",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			ac, err := resolveAdminClient()
			if err != nil {
				return err
			}
			var out map[string]any
			if err := ac.Do("GET", "/rbac/members", nil, &out); err != nil {
				return err
			}
			return printJSON(out)
		},
	}
}

func newRBACInviteCmd() *cobra.Command {
	var dryRun bool
	cmd := &cobra.Command{
		Use:   "invite <user> <group> <role>",
		Short: "Grant a role on a group and all descendants (preview with --dry-run)",
		Args:  cobra.ExactArgs(3),
		RunE: func(_ *cobra.Command, args []string) error {
			ac, err := resolveAdminClient()
			if err != nil {
				return err
			}
			var out map[string]any
			if err := ac.Do("POST", "/rbac/invite", map[string]any{
				"member": args[0], "group": args[1], "role": args[2], "dry_run": dryRun,
			}, &out); err != nil {
				return err
			}
			return printJSON(out)
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show the row diff without applying")
	return cmd
}

func newRBACRemoveCmd() *cobra.Command {
	var cascade, dryRun bool
	cmd := &cobra.Command{
		Use:   "remove <user> <group>",
		Short: "Remove a member from a group (R2: --cascade removes descendants too)",
		Args:  cobra.ExactArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			ac, err := resolveAdminClient()
			if err != nil {
				return err
			}
			var out map[string]any
			if err := ac.Do("POST", "/rbac/remove", map[string]any{
				"member": args[0], "group": args[1], "cascade": cascade, "dry_run": dryRun,
			}, &out); err != nil {
				return err
			}
			return printJSON(out)
		},
	}
	cmd.Flags().BoolVar(&cascade, "cascade", false, "Also remove from every descendant group (R2)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show the row diff without applying")
	return cmd
}

func newRBACGrantsCmd() *cobra.Command {
	var member, group string
	cmd := &cobra.Command{
		Use:   "grants",
		Short: "List grant rows (the materialized closure)",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			ac, err := resolveAdminClient()
			if err != nil {
				return err
			}
			q := url.Values{}
			if member != "" {
				q.Set("member", member)
			}
			if group != "" {
				q.Set("group", group)
			}
			path := "/rbac/grants"
			if len(q) > 0 {
				path += "?" + q.Encode()
			}
			var out map[string]any
			if err := ac.Do("GET", path, nil, &out); err != nil {
				return err
			}
			return printJSON(out)
		},
	}
	cmd.Flags().StringVar(&member, "member", "", "Filter by member id")
	cmd.Flags().StringVar(&group, "group", "", "Filter by group name or id")
	return cmd
}

func newRBACScopeCmd() *cobra.Command {
	var verb string
	cmd := &cobra.Command{
		Use:   "scope <user>",
		Short: "Show the compiled group scope for a member and verb",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			ac, err := resolveAdminClient()
			if err != nil {
				return err
			}
			q := url.Values{"member": {args[0]}, "verb": {verb}}
			var out map[string]any
			if err := ac.Do("GET", "/rbac/scope?"+q.Encode(), nil, &out); err != nil {
				return err
			}
			return printJSON(out)
		},
	}
	cmd.Flags().StringVar(&verb, "verb", "read", "Verb to compile: read|write|delete|manage")
	return cmd
}
