package namespace

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// containerDevNodes are the real device nodes every department container
// gets. They are bind-mounted from the host's /dev (via the old root,
// before it is detached) onto a fresh tmpfs — never mknod'd, never faked.
var containerDevNodes = []string{"null", "zero", "full", "random", "urandom", "tty"}

// ContainerInit is the re-exec entry point for department containers.
//
// SpawnDepartment starts /proc/self/exe with argv [..., "container-init"]
// and CLONE_NEW* flags; this function runs inside the child's fresh
// namespaces and performs the in-namespace half of container setup:
//
//  1. make all mounts private (nothing propagates back to the host),
//  2. pivot_root into the department rootfs,
//  3. mount /proc, /sys, /dev (tmpfs + real device nodes bind-mounted
//     from the old root) and /dev/pts,
//  4. detach the old root,
//  5. exec the department init.
//
// It never returns on success. A non-nil return means the container is
// unusable; the child exits non-zero and SpawnDepartment's liveness check
// turns that into a spawn error.
func ContainerInit() error {
	if os.Getenv("GHOST_CONTAINER_INIT") != "1" {
		return errors.New("container-init: refusing to run outside a spawned container (GHOST_CONTAINER_INIT!=1)")
	}
	rootfs := os.Getenv("GHOST_CONTAINER_ROOTFS")
	if rootfs == "" {
		return errors.New("container-init: GHOST_CONTAINER_ROOTFS not set")
	}
	initPath := os.Getenv("GHOST_CONTAINER_INIT_PATH")
	if initPath == "" {
		initPath = "/sbin/init"
	}

	// 1. No mount propagation to the host.
	if err := syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("container-init: make mounts private: %w", err)
	}

	// 2. pivot_root requires the new root to be a mountpoint.
	if err := syscall.Mount(rootfs, rootfs, "", syscall.MS_BIND|syscall.MS_REC, ""); err != nil {
		return fmt.Errorf("container-init: bind rootfs onto itself: %w", err)
	}
	pivotDir := filepath.Join(rootfs, ".pivot_old")
	if err := os.MkdirAll(pivotDir, 0o700); err != nil {
		return fmt.Errorf("container-init: mkdir .pivot_old: %w", err)
	}
	if err := syscall.PivotRoot(rootfs, pivotDir); err != nil {
		return fmt.Errorf("container-init: pivot_root: %w", err)
	}
	if err := os.Chdir("/"); err != nil {
		return fmt.Errorf("container-init: chdir /: %w", err)
	}

	// 3. Essential filesystems inside the new root.
	for _, d := range []string{"/proc", "/sys", "/dev", "/dev/pts"} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return fmt.Errorf("container-init: mkdir %s: %w", d, err)
		}
	}
	mount := func(source, target, fstype string, flags uintptr, data string) error {
		if err := syscall.Mount(source, target, fstype, flags, data); err != nil {
			return fmt.Errorf("container-init: mount %s on %s: %w", source, target, err)
		}
		return nil
	}
	if err := mount("proc", "/proc", "proc",
		syscall.MS_NOSUID|syscall.MS_NOEXEC|syscall.MS_NODEV, ""); err != nil {
		return err
	}
	if err := mount("sysfs", "/sys", "sysfs",
		syscall.MS_NOSUID|syscall.MS_NOEXEC|syscall.MS_NODEV|syscall.MS_RDONLY, ""); err != nil {
		return err
	}
	if err := mount("tmpfs", "/dev", "tmpfs",
		syscall.MS_NOSUID|syscall.MS_NOEXEC, "mode=755"); err != nil {
		return err
	}
	if err := mount("devpts", "/dev/pts", "devpts",
		syscall.MS_NOSUID|syscall.MS_NOEXEC, "newinstance,ptmxmode=0666,mode=0620"); err != nil {
		return err
	}
	if err := os.Symlink("pts/ptmx", "/dev/ptmx"); err != nil {
		return fmt.Errorf("container-init: symlink /dev/ptmx: %w", err)
	}

	// Real device nodes, bind-mounted from the old root (still visible at
	// /.pivot_old until step 4). Writable bind — /dev/null must sink writes.
	for _, dev := range containerDevNodes {
		src := filepath.Join("/.pivot_old/dev", dev)
		dst := filepath.Join("/dev", dev)
		f, err := os.OpenFile(dst, os.O_CREATE|os.O_RDWR, 0o666)
		if err != nil {
			return fmt.Errorf("container-init: create %s: %w", dst, err)
		}
		f.Close()
		if err := syscall.Mount(src, dst, "", syscall.MS_BIND, ""); err != nil {
			return fmt.Errorf("container-init: bind /dev/%s: %w", dev, err)
		}
	}

	// 4. Detach the old root — the container can no longer reach host paths.
	if err := syscall.Unmount("/.pivot_old", syscall.MNT_DETACH); err != nil {
		return fmt.Errorf("container-init: detach old root: %w", err)
	}

	// 5. Become the department init.
	if err := syscall.Exec(initPath, []string{initPath}, os.Environ()); err != nil {
		return fmt.Errorf("container-init: exec %s: %w", initPath, err)
	}
	return nil // unreachable
}
