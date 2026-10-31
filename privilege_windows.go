//go:build windows

package localtls

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// callerIsPrivileged reports whether the current process runs as LocalSystem
// or with an elevated token that is a member of BUILTIN\Administrators. These
// are the principals the expected Local-TLS key DACL grants full access, so for
// them the expected DACL is not a cause of a "not found or not accessible" open.
// That does not make such a result proof of absence: a key with another DACL,
// provider state or token conditions can produce the same result. It does not
// change any privilege.
func callerIsPrivileged() (bool, error) {
	token := windows.GetCurrentProcessToken()

	user, err := token.GetTokenUser()
	if err != nil {
		return false, fmt.Errorf("read process token user: %w", err)
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return false, fmt.Errorf("create LocalSystem SID: %w", err)
	}
	if user.User.Sid.Equals(system) {
		return true, nil
	}

	if !token.IsElevated() {
		return false, nil
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return false, fmt.Errorf("create Administrators SID: %w", err)
	}
	// Token 0 checks the effective token of the calling thread/process.
	member, err := windows.Token(0).IsMember(admins)
	if err != nil {
		return false, fmt.Errorf("check Administrators membership: %w", err)
	}
	return member, nil
}
