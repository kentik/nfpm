package deb

import (
	"archive/tar"
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/goreleaser/nfpm"
)

// nolint: gochecknoglobals
var update = flag.Bool("update", false, "update .golden files")

func exampleInfo() *nfpm.Info {
	return nfpm.WithDefaults(&nfpm.Info{
		Name:        "foo",
		Arch:        "amd64",
		Description: "Foo does things",
		Priority:    "extra",
		Maintainer:  "Carlos A Becker <pkg@carlosbecker.com>",
		Version:     "v1.0.0",
		Section:     "default",
		Homepage:    "http://carlosbecker.com",
		Vendor:      "nope",
		Overridables: nfpm.Overridables{
			Depends: []string{
				"bash",
			},
			Recommends: []string{
				"git",
			},
			Suggests: []string{
				"bash",
			},
			Replaces: []string{
				"svn",
			},
			Provides: []string{
				"bzr",
			},
			Conflicts: []string{
				"zsh",
			},
			Files: map[string]string{
				"../testdata/fake":          "/usr/local/bin/fake",
				"../testdata/whatever.conf": "/usr/share/doc/fake/fake.txt",
			},
			ConfigFiles: map[string]string{
				"../testdata/whatever.conf": "/etc/fake/fake.conf",
			},
			EmptyFolders: []string{
				"/var/log/whatever",
				"/usr/share/whatever",
			},
		},
	})
}

func TestDeb(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		arch := arch
		t.Run(arch, func(t *testing.T) {
			info := exampleInfo()
			info.Arch = arch
			var err = Default.Package(info, ioutil.Discard)
			assert.NoError(t, err)
		})
	}
}

func extractDebVersion(deb *bytes.Buffer) string {
	for _, s := range strings.Split(deb.String(), "\n") {
		if strings.Contains(s, "Version: ") {
			return strings.TrimPrefix(s, "Version: ")
		}
	}
	return ""
}

func TestDebVersionWithDash(t *testing.T) {
	info := exampleInfo()
	info.Version = "1.0.0-beta"
	var err = Default.Package(info, ioutil.Discard)
	assert.NoError(t, err)
}

func TestDebVersion(t *testing.T) {
	info := exampleInfo()
	info.Version = "1.0.0" //nolint:golint,goconst
	var buf bytes.Buffer
	var err = writeControl(&buf, controlData{info, 0})
	assert.NoError(t, err)
	var v = extractDebVersion(&buf)
	assert.Equal(t, "1.0.0", v)
}

func TestDebVersionWithRelease(t *testing.T) {
	info := exampleInfo()
	info.Version = "1.0.0" //nolint:golint,goconst
	info.Release = "1"
	var buf bytes.Buffer
	var err = writeControl(&buf, controlData{info, 0})
	assert.NoError(t, err)
	var v = extractDebVersion(&buf)
	assert.Equal(t, "1.0.0-1", v)
}

func TestDebVersionWithPrerelease(t *testing.T) {
	info := exampleInfo()
	info.Version = "1.0.0" //nolint:golint,goconst
	info.Prerelease = "1"
	var buf bytes.Buffer
	var err = writeControl(&buf, controlData{info, 0})
	assert.NoError(t, err)
	var v = extractDebVersion(&buf)
	assert.Equal(t, "1.0.0~1", v)
}

func TestDebVersionWithReleaseAndPrerelease(t *testing.T) {
	info := exampleInfo()
	info.Version = "1.0.0" //nolint:golint,goconst
	info.Release = "2"
	info.Prerelease = "rc1"
	var buf bytes.Buffer
	var err = writeControl(&buf, controlData{info, 0})
	assert.NoError(t, err)
	var v = extractDebVersion(&buf)
	assert.Equal(t, "1.0.0-2~rc1", v)
}

func TestControl(t *testing.T) {
	var w bytes.Buffer
	assert.NoError(t, writeControl(&w, controlData{
		Info:          exampleInfo(),
		InstalledSize: 10,
	}))
	var golden = "testdata/control.golden"
	if *update {
		require.NoError(t, ioutil.WriteFile(golden, w.Bytes(), 0600))
	}
	bts, err := ioutil.ReadFile(golden) //nolint:gosec
	assert.NoError(t, err)
	assert.Equal(t, string(bts), w.String())
}

func newScriptInsideTarGzFromFile(out *tar.Writer, path, dest string) error {
	var buf = bytes.Buffer{}
	if err := addScriptFromFile(&buf, path); err != nil {
		return err
	}
	if err := newScriptInsideTarGz(out, buf.Bytes(), dest); err != nil {
		return err
	}

	return nil
}

// test adding script as file
func TestScripts(t *testing.T) {
	var w bytes.Buffer
	var out = tar.NewWriter(&w)
	path := "../testdata/scripts/preinstall.sh"
	assert.Error(t, newScriptInsideTarGzFromFile(out, "doesnotexit", "preinst"))
	assert.NoError(t, newScriptInsideTarGzFromFile(out, path, "preinst"))
	var in = tar.NewReader(&w)
	header, err := in.Next()
	assert.NoError(t, err)
	assert.Equal(t, "preinst", header.FileInfo().Name())
	mode, err := strconv.ParseInt("0755", 8, 64)
	assert.NoError(t, err)
	assert.Equal(t, int64(header.FileInfo().Mode()), mode)
	data, err := ioutil.ReadAll(in)
	assert.NoError(t, err)
	org, err := ioutil.ReadFile(path)
	assert.NoError(t, err)
	assert.Equal(t, org, data)
}

// test adding script as string
func TestScripts2(t *testing.T) {
	var w bytes.Buffer
	var out = tar.NewWriter(&w)
	script := "#!/bin/sh\n"

	buf := bytes.Buffer{}
	assert.NoError(t, addScriptFromString(&buf, script))
	assert.NoError(t, newScriptInsideTarGz(out, buf.Bytes(), "preinst"))

	var in = tar.NewReader(&w)
	header, err := in.Next()
	assert.NoError(t, err)
	assert.Equal(t, "preinst", header.FileInfo().Name())
	mode, err := strconv.ParseInt("0755", 8, 64)
	assert.NoError(t, err)
	assert.Equal(t, int64(header.FileInfo().Mode()), mode)
	data, err := ioutil.ReadAll(in)
	assert.NoError(t, err)

	buf = bytes.Buffer{}
	buf.WriteString(script)
	buf.WriteString("\n")
	assert.Equal(t, buf.Bytes(), data)
}

// test adding script as string and file
func TestScripts3(t *testing.T) {
	var w bytes.Buffer
	var out = tar.NewWriter(&w)
	path := "../testdata/scripts/preinstall.sh"
	script := "#!/bin/sh\n"

	buf := bytes.Buffer{}
	assert.NoError(t, addScriptFromString(&buf, script))
	assert.NoError(t, addScriptFromFile(&buf, path))
	assert.NoError(t, newScriptInsideTarGz(out, buf.Bytes(), "preinst"))

	var in = tar.NewReader(&w)
	header, err := in.Next()
	assert.NoError(t, err)
	assert.Equal(t, "preinst", header.FileInfo().Name())
	mode, err := strconv.ParseInt("0755", 8, 64)
	assert.NoError(t, err)
	assert.Equal(t, int64(header.FileInfo().Mode()), mode)
	data, err := ioutil.ReadAll(in)
	assert.NoError(t, err)

	org, err := ioutil.ReadFile(path)
	assert.NoError(t, err)
	buf = bytes.Buffer{}
	buf.WriteString(script)
	buf.WriteString("\n")
	buf.Write(org)
	assert.Equal(t, buf.Bytes(), data)
}

func TestNoJoinsControl(t *testing.T) {
	var w bytes.Buffer
	assert.NoError(t, writeControl(&w, controlData{
		Info: nfpm.WithDefaults(&nfpm.Info{
			Name:        "foo",
			Arch:        "amd64",
			Description: "Foo does things",
			Priority:    "extra",
			Maintainer:  "Carlos A Becker <pkg@carlosbecker.com>",
			Version:     "v1.0.0",
			Section:     "default",
			Homepage:    "http://carlosbecker.com",
			Vendor:      "nope",
			Overridables: nfpm.Overridables{
				Depends:     []string{},
				Recommends:  []string{},
				Suggests:    []string{},
				Replaces:    []string{},
				Provides:    []string{},
				Conflicts:   []string{},
				Files:       map[string]string{},
				ConfigFiles: map[string]string{},
			},
		}),
		InstalledSize: 10,
	}))
	var golden = "testdata/control2.golden"
	if *update {
		require.NoError(t, ioutil.WriteFile(golden, w.Bytes(), 0600))
	}
	bts, err := ioutil.ReadFile(golden) //nolint:gosec
	assert.NoError(t, err)
	assert.Equal(t, string(bts), w.String())
}

func TestDebFileDoesNotExist(t *testing.T) {
	var err = Default.Package(
		nfpm.WithDefaults(&nfpm.Info{
			Name:        "foo",
			Arch:        "amd64",
			Description: "Foo does things",
			Priority:    "extra",
			Maintainer:  "Carlos A Becker <pkg@carlosbecker.com>",
			Version:     "1.0.0",
			Section:     "default",
			Homepage:    "http://carlosbecker.com",
			Vendor:      "nope",
			Overridables: nfpm.Overridables{
				Depends: []string{
					"bash",
				},
				Files: map[string]string{
					"../testdata/": "/usr/local/bin/fake",
				},
				ConfigFiles: map[string]string{
					"../testdata/whatever.confzzz": "/etc/fake/fake.conf",
				},
			},
		}),
		ioutil.Discard,
	)
	assert.EqualError(t, err, "../testdata/whatever.confzzz: file does not exist")
}

func TestDebNoFiles(t *testing.T) {
	var err = Default.Package(
		nfpm.WithDefaults(&nfpm.Info{
			Name:        "foo",
			Arch:        "amd64",
			Description: "Foo does things",
			Priority:    "extra",
			Maintainer:  "Carlos A Becker <pkg@carlosbecker.com>",
			Version:     "1.0.0",
			Section:     "default",
			Homepage:    "http://carlosbecker.com",
			Vendor:      "nope",
			Overridables: nfpm.Overridables{
				Depends: []string{
					"bash",
				},
			},
		}),
		ioutil.Discard,
	)
	assert.NoError(t, err)
}

func TestDebNoInfo(t *testing.T) {
	var err = Default.Package(nfpm.WithDefaults(&nfpm.Info{}), ioutil.Discard)
	assert.NoError(t, err)
}

func TestConffiles(t *testing.T) {
	out := conffiles(&nfpm.Info{
		Overridables: nfpm.Overridables{
			ConfigFiles: map[string]string{
				"foo": "/etc/foo",
				"bar": "/etc/bar:root:644",
			},
		},
	})
	assert.Equal(t, "/etc/foo\n/etc/bar\n", string(out), "should have a trailing empty line")
}

func TestPathsToCreate(t *testing.T) {
	for path, parts := range map[string][]string{
		"/usr/share/doc/whatever/foo.md": {"usr", "usr/share", "usr/share/doc", "usr/share/doc/whatever"},
		"/var/moises":                    {"var"},
		"/":                              {},
	} {
		parts := parts
		path := path
		t.Run(fmt.Sprintf("path: '%s'", path), func(t *testing.T) {
			assert.Equal(t, parts, pathsToCreate(path))
		})
	}
}

func TestMinimalFields(t *testing.T) {
	var w bytes.Buffer
	assert.NoError(t, writeControl(&w, controlData{
		Info: nfpm.WithDefaults(&nfpm.Info{
			Name:        "minimal",
			Arch:        "arm64",
			Description: "Minimal does nothing",
			Priority:    "extra",
			Version:     "1.0.0",
			Section:     "default",
		}),
	}))
	var golden = "testdata/minimal.golden"
	if *update {
		require.NoError(t, ioutil.WriteFile(golden, w.Bytes(), 0600))
	}
	bts, err := ioutil.ReadFile(golden) //nolint:gosec
	assert.NoError(t, err)
	assert.Equal(t, string(bts), w.String())
}

func TestDebEpoch(t *testing.T) {
	var w bytes.Buffer
	assert.NoError(t, writeControl(&w, controlData{
		Info: nfpm.WithDefaults(&nfpm.Info{
			Name:        "withepoch",
			Arch:        "arm64",
			Description: "Has an epoch added to it's version",
			Priority:    "extra",
			Epoch:       "2",
			Version:     "1.0.0",
			Section:     "default",
		}),
	}))
	var golden = "testdata/withepoch.golden"
	if *update {
		require.NoError(t, ioutil.WriteFile(golden, w.Bytes(), 0600))
	}
	bts, err := ioutil.ReadFile(golden) //nolint:gosec
	assert.NoError(t, err)
	assert.Equal(t, string(bts), w.String())
}

func TestDebRules(t *testing.T) {
	var w bytes.Buffer
	assert.NoError(t, writeControl(&w, controlData{
		Info: nfpm.WithDefaults(&nfpm.Info{
			Name:        "lala",
			Arch:        "arm64",
			Description: "Has rules script",
			Priority:    "extra",
			Epoch:       "2",
			Version:     "1.2.0",
			Section:     "default",
			Overridables: nfpm.Overridables{
				Deb: nfpm.Deb{
					Scripts: nfpm.DebScripts{
						Rules: "foo.sh",
					},
				},
			},
		}),
	}))
	var golden = "testdata/rules.golden"
	if *update {
		require.NoError(t, ioutil.WriteFile(golden, w.Bytes(), 0600))
	}
	bts, err := ioutil.ReadFile(golden) //nolint:gosec
	assert.NoError(t, err)
	assert.Equal(t, string(bts), w.String())
}

func TestMultilineFields(t *testing.T) {
	var w bytes.Buffer
	assert.NoError(t, writeControl(&w, controlData{
		Info: nfpm.WithDefaults(&nfpm.Info{
			Name:        "multiline",
			Arch:        "riscv64",
			Description: "This field is a\nmultiline field\nthat should work.",
			Priority:    "extra",
			Version:     "1.0.0",
			Section:     "default",
		}),
	}))
	var golden = "testdata/multiline.golden"
	if *update {
		require.NoError(t, ioutil.WriteFile(golden, w.Bytes(), 0600))
	}
	bts, err := ioutil.ReadFile(golden) //nolint:gosec
	assert.NoError(t, err)
	assert.Equal(t, string(bts), w.String())
}
