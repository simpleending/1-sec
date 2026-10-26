package core

import (
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWindowsPrivatePathRemovesBroadACLs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	if err := RestrictPrivatePath(path, false); err != nil {
		t.Fatal(err)
	}
	actual, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	sddl := actual.String()
	for _, broad := range []string{";;;WD)", ";;;AU)", ";;;BU)"} {
		if strings.Contains(sddl, broad) {
			t.Fatal("broad read permission remains", sddl)
		}
	}
	user, _ := windows.GetCurrentProcessToken().GetTokenUser()
	if !strings.Contains(sddl, user.User.Sid.String()) || !strings.Contains(sddl, "D:P") {
		t.Fatal("missing protected owner ACL", sddl)
	}
	if _, err := os.ReadFile(path); err != nil {
		t.Fatal("owner cannot read", err)
	}
}
