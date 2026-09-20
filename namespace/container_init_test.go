package namespace

import (
	"os"
	"testing"
)

// The full pivot_root path needs root + userns + mountns and cannot run
// in unit tests; these cover the guard rails. Runtime verification
// (real container spawn on a root host) is documented in CHANGELOG.

func TestContainerInit_RefusesWithoutEnv(t *testing.T) {
	os.Unsetenv("GHOST_CONTAINER_INIT")
	os.Unsetenv("GHOST_CONTAINER_ROOTFS")
	if err := ContainerInit(); err == nil {
		t.Fatal("ContainerInit ran without GHOST_CONTAINER_INIT=1")
	}
}

func TestContainerInit_RequiresRootfs(t *testing.T) {
	t.Setenv("GHOST_CONTAINER_INIT", "1")
	os.Unsetenv("GHOST_CONTAINER_ROOTFS")
	if err := ContainerInit(); err == nil {
		t.Fatal("ContainerInit ran without GHOST_CONTAINER_ROOTFS")
	}
}
