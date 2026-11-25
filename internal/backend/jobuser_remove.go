package backend

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// RemoveJobUsersOptions says where the job users are.
type RemoveJobUsersOptions struct {
	// StateDir is the job-user state folder the agent was given. Empty means
	// there is none to remove.
	StateDir string
	// UsersDir is where homes live. Empty means /Users.
	UsersDir string
	Logger   *slog.Logger

	system jobUserSystem
}

// RemoveJobUsers undoes what a job-user agent set up: it stops everything the
// job users run, and deletes the accounts, their homes, the trash and the group.
// It touches only
// accounts that are exactly what Zoomies makes, and refuses if any account or
// group in its range is something else, because deleting a person's account is
// not a thing to do on the strength of a name. The agent must not be running:
// the caller checks that.
func RemoveJobUsers(ctx context.Context, o RemoveJobUsersOptions) error {
	log := o.Logger
	if log == nil {
		log = slog.Default()
	}
	if strings.TrimSpace(o.StateDir) == "" {
		return fmt.Errorf("backend: removing job users needs the state folder the agent used, so that it can be deleted too")
	}
	u, err := buildJobUsers(JobUserOptions{Capacity: jobUserMaxCapacity, StateDir: o.StateDir, UsersDir: o.UsersDir, system: o.system}, "", log)
	if err != nil {
		return err
	}
	return u.removeAll(ctx)
}

func (u *jobUsers) removeAll(ctx context.Context) error {
	out, err := u.run(ctx, "/usr/bin/dscl", ".", "-list", "/Users", "UniqueID")
	if err != nil {
		return fmt.Errorf("listing the local accounts: %w", err)
	}
	users := parseJobUserIDs(out)
	out, err = u.run(ctx, "/usr/bin/dscl", ".", "-list", "/Groups", "PrimaryGroupID")
	if err != nil {
		return fmt.Errorf("listing the local groups: %w", err)
	}
	groups := parseJobUserIDs(out)
	if err := checkJobUserAccounts(users, groups); err != nil {
		return err
	}

	var failed []string
	for _, s := range u.slots {
		if _, ok := users[s.name]; !ok {
			continue
		}
		// Stopped and booted out first: an account cannot be deleted from under
		// the processes that run as it.
		if err := u.stopProcesses(ctx, s); err != nil {
			failed = append(failed, fmt.Sprintf("%s: %v", s.name, err))
			continue
		}
		if err := u.bootoutDomains(ctx, s); err != nil {
			failed = append(failed, fmt.Sprintf("%s: %v", s.name, err))
			continue
		}
		if _, err := u.run(ctx, "/usr/sbin/sysadminctl", "-deleteUser", s.name); err != nil {
			failed = append(failed, fmt.Sprintf("%s: %v", s.name, err))
			continue
		}
		if err := u.sys.RemoveAll(u.home(s)); err != nil {
			failed = append(failed, fmt.Sprintf("%s: removing its home: %v", s.name, err))
		}
		u.log.Info("removed a job user", "slot", s.name)
	}
	if len(failed) > 0 {
		return fmt.Errorf("backend: could not remove every job user, and the group was left as it is so that this can be run again: %s", strings.Join(failed, "; "))
	}

	if err := u.sys.RemoveAll(u.trashDir); err != nil {
		return fmt.Errorf("removing the trash folder %s: %w", u.trashDir, err)
	}
	if _, ok := groups[jobUserGroup]; ok {
		if _, err := u.run(ctx, "/usr/bin/dscl", ".", "-delete", "/Groups/"+jobUserGroup); err != nil {
			return fmt.Errorf("deleting the group %s: %w", jobUserGroup, err)
		}
	}
	if filepath.Base(u.stateDir) == "job-users" {
		if err := os.RemoveAll(u.stateDir); err != nil {
			return fmt.Errorf("removing %s: %w", u.stateDir, err)
		}
	}
	return nil
}
