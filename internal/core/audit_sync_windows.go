package core

// Go/Windows does not expose a portable directory Sync guarantee. File commits
// use FlushFileBuffers through os.File.Sync; power-loss durability remains a
// collector storage/OS requirement and is not inferred from restart tests.
func syncAuditDirectory(string) error { return nil }
