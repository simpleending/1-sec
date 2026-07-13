package main

// ---------------------------------------------------------------------------
// cmd_docker.go — manage the Docker Compose deployment
// ---------------------------------------------------------------------------

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func cmdDocker(args []string) {
	fs := flag.NewFlagSet("docker", flag.ExitOnError)
	composeFile := fs.String("compose-file", "deploy/docker/docker-compose.yml", "Path to docker-compose.yml")
	envFile := fs.String("env-file", ".env", "Path to .env file")
	fs.Parse(args)

	subcmds := fs.Args()
	if len(subcmds) == 0 {
		cmdHelp("docker")
		os.Exit(0)
	}

	sub := subcmds[0]

	baseArgs := []string{"compose", "--file", *composeFile}
	if _, err := os.Stat(*envFile); err == nil {
		baseArgs = append(baseArgs, "--env-file", *envFile)
	}

	var dockerArgs []string
	switch sub {
	case "up":
		dockerArgs = append(baseArgs, "up", "--detach", "--remove-orphans")
		fmt.Fprintf(os.Stderr, "%s Starting 1SEC via Docker Compose...\n", dim("▸"))
	case "down":
		dockerArgs = append(baseArgs, "down")
		fmt.Fprintf(os.Stderr, "%s Stopping 1SEC containers...\n", dim("▸"))
	case "logs":
		dockerArgs = append(baseArgs, "logs", "--tail=100")
	case "status":
		dockerArgs = append(baseArgs, "ps")
	case "build":
		dockerArgs = append(baseArgs, "build", "--no-cache")
		fmt.Fprintf(os.Stderr, "%s Building 1SEC Docker image from source...\n", dim("▸"))
	case "pull":
		dockerArgs = append(baseArgs, "pull")
		fmt.Fprintf(os.Stderr, "%s Pulling latest 1SEC image...\n", dim("▸"))
	default:
		fmt.Fprintf(os.Stderr, red("error: ")+"unknown docker subcommand %q\n\n", sub)
		cmdHelp("docker")
		os.Exit(1)
	}

	if err := execDocker(dockerArgs); err != nil {
		errorf("docker %s failed: %v", sub, err)
	}
}

func execDocker(args []string) error {
	dockerBin, err := findExecutable("docker")
	if err != nil {
		return fmt.Errorf("docker not found in PATH — install Docker from https://docs.docker.com/get-docker/")
	}
	return runSubprocess(dockerBin, args)
}

func findExecutable(name string) (string, error) {
	pathEnv := os.Getenv("PATH")
	if pathEnv == "" {
		return "", fmt.Errorf("%s not found", name)
	}
	sep := ":"
	if os.PathSeparator == '\\' {
		sep = ";"
		name += ".exe"
	}
	for _, dir := range strings.Split(pathEnv, sep) {
		full := dir + string(os.PathSeparator) + name
		// #nosec G703 -- name is a fixed executable basename and dir comes from PATH.
		if fi, err := os.Stat(full); err == nil && !fi.IsDir() {
			return full, nil
		}
	}
	return "", fmt.Errorf("%s not found in PATH", name)
}

func runSubprocess(bin string, args []string) error {
	cmd := exec.Command(bin, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		return err
	}
	return nil
}
