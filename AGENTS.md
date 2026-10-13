# Repository instructions

- Consult the current official documentation for frameworks, APIs, languages, and protocols before changing their behavior.
- A vulnerability intelligence cycle includes implementation. After running the local `scripts/weekly_vuln_report.py`, verify the proposed findings against source, primary evidence, and reproducible tests; implement applicable fixes in the existing modules.
- Use the reporting period the user requests. Weekly normally means seven days; a requested month means a month. Do not silently expand the window.
- Give every action item a tested disposition: implemented, already covered, deferred with a concrete reason, or rejected with evidence. Update the local report manifest and `reports/report-index.json` so the next cycle inherits the real status.
- Add regression tests for security behavior and run the affected tests, engine build, vet, and vulnerability reachability scan. A feed count or model recommendation alone does not establish an exploitable product vulnerability.
- Check the repository-wide dependency gate, including the Rust sidecar. For Rust changes, run formatting, Clippy, audit, and appropriate tests; document platform constraints and existing maintenance exceptions instead of hiding new findings.
- Record the implemented changes and their limits in `docs/security-updates/`. Raw reports and local scripts stay ignored.
- Update the existing user-facing blog entry in the separate `web` repository after the code changes are verified. Describe actual changes, required telemetry, and remaining limits; do not present proposals as shipped protections.
- When commit/push is authorized, commit and push the tool changes first, then the blog. Verify the remote heads and report both commits. The other nested website checkout can contain unrelated work; inspect each checkout's remote and status before using it.
