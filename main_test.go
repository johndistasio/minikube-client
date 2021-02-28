package main

import (
	"path/filepath"
	"testing"
)

func TestResolveKubeConfigPath_Default(t *testing.T) {
	home := "/home/test"

	env := ""

	expected := filepath.Join(home, ".kube/config")

	actual := resolveKubeConfigPath(home, env)

	if expected != actual {
		t.Errorf("Incorrectly resolved \"~/.kube/config\"; expected \"%s\" got \"%s\"", expected, actual)
	}
}

func TestResolveKubeConfigPath_KUBECONFIG_Tilde(t *testing.T) {
	home := "/home/test"

	env := "~/kube-config"

	expected := filepath.Join(home, "kube-config")

	actual := resolveKubeConfigPath(home, env)

	if expected != actual {
		t.Errorf("Incorrectly resolved \"~\" in \"$KUBECONFIG\"; expected \"%s\" got \"%s\"", expected, actual)
	}
}

func TestResolveKubeConfigPath_KUBECONFIG_Var(t *testing.T) {
	home := "/home/test"

	env := "$HOME/dir/.kube/config"

	expected := filepath.Join(home, "dir/.kube/config")

	actual := resolveKubeConfigPath(home, env)

	if expected != actual {
		t.Errorf("Incorrectly resolved \"$HOME\" in \"$KUBECONFIG\"; expected \"%s\" got \"%s\"", expected, actual)
	}
}
