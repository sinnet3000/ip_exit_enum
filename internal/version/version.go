package version

import "runtime/debug"

// Version is the build version. Set via -ldflags for releases,
// otherwise falls back to VCS info from the local build.
var Version = "dev"

func init() {
	if Version != "dev" {
		return
	}
	Version = getVersionFromVCS()
}

func getVersionFromVCS() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "dev"
	}

	if v := info.Main.Version; v != "" && v != "(devel)" {
		return v
	}

	var revision string
	var modified bool

	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			revision = setting.Value
		case "vcs.modified":
			modified = setting.Value == "true"
		}
	}

	if revision == "" {
		return "dev"
	}

	if len(revision) > 7 {
		revision = revision[:7]
	}

	if modified {
		revision += "-dirty"
	}

	return revision
}
