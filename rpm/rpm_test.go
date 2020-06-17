package rpm

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sassoftware/go-rpmutils"
	"github.com/stretchr/testify/assert"

	"github.com/goreleaser/nfpm"
)

const (
	tagVersion     = 0x03e9 // 1001
	tagRelease     = 0x03ea // 1002
	tagEpoch       = 0x03eb // 1003
	tagSummary     = 0x03ec // 1004
	tagDescription = 0x03ed // 1005
	tagGroup       = 0x03f8 // 1016
	tagPrein       = 0x03ff // 1023
	tagPostin      = 0x0400 // 1024
	tagPreun       = 0x0401 // 1025
	tagPostun      = 0x0402 // 1026
)

func exampleInfo() *nfpm.Info {
	return nfpm.WithDefaults(&nfpm.Info{
		Name:        "foo",
		Arch:        "amd64",
		Description: "Foo does things",
		Priority:    "extra",
		Maintainer:  "Carlos A Becker <pkg@carlosbecker.com>",
		Version:     "1.0.0",
		Section:     "default",
		Homepage:    "http://carlosbecker.com",
		Vendor:      "nope",
		License:     "MIT",
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
				"../testdata/fake": "/usr/local/bin/fake",
			},
			ConfigFiles: map[string]string{
				"../testdata/whatever.conf": "/etc/fake/fake.conf",
			},
			EmptyFolders: []string{
				"/var/log/whatever",
				"/usr/share/whatever",
			},
			Scripts: nfpm.Scripts{
				PreInstall:  "../testdata/scripts/preinstall.sh",
				PostInstall: "../testdata/scripts/postinstall.sh",
				PreRemove:   "../testdata/scripts/preremove.sh",
				PostRemove:  "../testdata/scripts/postremove.sh",
			},
		},
	})
}

func exampleScripts(info *nfpm.Info) (*Scripts, error) {
	scripts := &Scripts{}

	var (
		data []byte
		err  error
	)

	for _, systemdUnit := range info.SystemdUnits {
		unit := filepath.Base(systemdUnit)
		scripts.PostInstall = append(scripts.PostInstall,
			strings.ReplaceAll(scriptSystemdPostinst, "%{package_unit}", unit))
		scripts.PreRemove = append(scripts.PreRemove,
			strings.ReplaceAll(scriptSystemdPreun, "%{package_unit}", unit))
		scripts.PostRemove = append(scripts.PostRemove,
			strings.ReplaceAll(scriptSystemdPostun, "%{package_unit}", unit))
	}

	data, err = ioutil.ReadFile(info.Scripts.PreInstall)
	if err != nil {
		return nil, err
	}
	scripts.PreInstall = append(scripts.PreInstall, string(data))

	data, err = ioutil.ReadFile(info.Scripts.PostInstall)
	if err != nil {
		return nil, err
	}
	scripts.PostInstall = append(scripts.PostInstall, string(data))

	data, err = ioutil.ReadFile(info.Scripts.PreRemove)
	if err != nil {
		return nil, err
	}
	scripts.PreRemove = append(scripts.PreRemove, string(data))

	data, err = ioutil.ReadFile(info.Scripts.PostRemove)
	if err != nil {
		return nil, err
	}
	scripts.PostRemove = append(scripts.PostRemove, string(data))

	return scripts, nil
}

func TestRPM(t *testing.T) {
	f, err := ioutil.TempFile("", "test.rpm")
	defer func() {
		_ = f.Close()
		err = os.Remove(f.Name())
		assert.NoError(t, err)
	}()

	assert.NoError(t, Default.Package(exampleInfo(), f))

	file, err := os.OpenFile(f.Name(), os.O_RDONLY, 0600) //nolint:gosec
	assert.NoError(t, err)
	rpm, err := rpmutils.ReadRpm(file)
	assert.NoError(t, err)

	version, err := rpm.Header.GetString(tagVersion)
	assert.NoError(t, err)
	assert.Equal(t, "1.0.0", version)

	release, err := rpm.Header.GetString(tagRelease)
	assert.NoError(t, err)
	assert.Equal(t, "1", release)

	epoch, err := rpm.Header.Get(tagEpoch)
	assert.NoError(t, err)
	epochUint32, ok := epoch.([]uint32)
	assert.Len(t, epochUint32, 1)
	assert.True(t, ok)
	assert.Equal(t, uint32(0), epochUint32[0])

	group, err := rpm.Header.GetString(tagGroup)
	assert.NoError(t, err)
	assert.Equal(t, "Development/Tools", group)

	summary, err := rpm.Header.GetString(tagSummary)
	assert.NoError(t, err)
	assert.Equal(t, "Foo does things", summary)

	description, err := rpm.Header.GetString(tagDescription)
	assert.NoError(t, err)
	assert.Equal(t, "Foo does things", description)
}

func TestWithRPMTags(t *testing.T) {
	f, err := ioutil.TempFile("", "test.rpm")
	defer func() {
		_ = f.Close()
		err = os.Remove(f.Name())
		assert.NoError(t, err)
	}()

	var info = exampleInfo()
	info.Release = "3"
	info.Epoch = "42"
	info.RPM = nfpm.RPM{
		Group: "default",
	}
	info.Description = "first line\nsecond line\nthird line"
	assert.NoError(t, Default.Package(info, f))

	file, err := os.OpenFile(f.Name(), os.O_RDONLY, 0600) //nolint:gosec
	assert.NoError(t, err)

	rpm, err := rpmutils.ReadRpm(file)
	assert.NoError(t, err)

	version, err := rpm.Header.GetString(tagVersion)
	assert.NoError(t, err)
	assert.Equal(t, "1.0.0", version)

	release, err := rpm.Header.GetString(tagRelease)
	assert.NoError(t, err)
	assert.Equal(t, "3", release)

	epoch, err := rpm.Header.Get(tagEpoch)
	assert.NoError(t, err)
	epochUint32, ok := epoch.([]uint32)
	assert.Len(t, epochUint32, 1)
	assert.True(t, ok)
	assert.Equal(t, uint32(42), epochUint32[0])

	group, err := rpm.Header.GetString(tagGroup)
	assert.NoError(t, err)
	assert.Equal(t, "default", group)

	summary, err := rpm.Header.GetString(tagSummary)
	assert.NoError(t, err)
	assert.Equal(t, "first line", summary)

	description, err := rpm.Header.GetString(tagDescription)
	assert.NoError(t, err)
	assert.Equal(t, info.Description, description)
}

func TestRPMVersion(t *testing.T) {
	info := exampleInfo()
	info.Version = "1.0.0" //nolint:golint,goconst
	meta, err := buildRPMMeta(info)
	assert.NoError(t, err)
	assert.Equal(t, "1.0.0", meta.Version)
	assert.Equal(t, "1", meta.Release)
}

func TestRPMVersionWithRelease(t *testing.T) {
	info := exampleInfo()
	info.Version = "1.0.0" //nolint:golint,goconst
	info.Release = "2"
	meta, err := buildRPMMeta(info)
	assert.NoError(t, err)
	assert.Equal(t, "1.0.0", meta.Version)
	assert.Equal(t, "2", meta.Release)
}

func TestRPMVersionWithPrerelease(t *testing.T) {
	// https://fedoraproject.org/wiki/Package_Versioning_Examples#Complex_versioning_examples
	info := exampleInfo()
	info.Version = "1.0.0" //nolint:golint,goconst
	info.Prerelease = "rc1"
	meta, err := buildRPMMeta(info)
	assert.NoError(t, err)
	assert.Equal(t, "1.0.0", meta.Version)
	assert.Equal(t, "0.1.rc1", meta.Release)
}

func TestRPMVersionWithReleaseAndPrerelease(t *testing.T) {
	// https://fedoraproject.org/wiki/Package_Versioning_Examples#Complex_versioning_examples
	info := exampleInfo()
	info.Version = "1.0.0" //nolint:golint,goconst
	info.Release = "0.2"
	info.Prerelease = "rc1"
	meta, err := buildRPMMeta(info)
	assert.NoError(t, err)
	assert.Equal(t, "1.0.0", meta.Version)
	assert.Equal(t, "0.2.rc1", meta.Release)
}

func TestWithInvalidEpoch(t *testing.T) {
	f, err := ioutil.TempFile("", "test.rpm")
	defer func() {
		_ = f.Close()
		err = os.Remove(f.Name())
		assert.NoError(t, err)
	}()

	var info = exampleInfo()
	info.Release = "3"
	info.Epoch = "-1"
	info.RPM = nfpm.RPM{
		Group: "default",
	}
	info.Description = "first line\nsecond line\nthird line"
	assert.Error(t, Default.Package(info, f))
}

func TestRPMScripts(t *testing.T) {
	info := exampleInfo()
	f, err := ioutil.TempFile(".", fmt.Sprintf("%s-%s-*.rpm", info.Name, info.Version))
	defer func() {
		_ = f.Close()
		err = os.Remove(f.Name())
		assert.NoError(t, err)
	}()
	assert.NoError(t, err)
	err = Default.Package(info, f)
	assert.NoError(t, err)
	file, err := os.OpenFile(f.Name(), os.O_RDONLY, 0600) //nolint:gosec
	assert.NoError(t, err)
	rpm, err := rpmutils.ReadRpm(file)
	assert.NoError(t, err)

	data, err := rpm.Header.GetString(tagPrein)
	assert.NoError(t, err)
	assert.Equal(t, `#!/bin/bash

echo "Preinstall" > /dev/null
`, data, "Preinstall script does not match")

	data, err = rpm.Header.GetString(tagPreun)
	assert.NoError(t, err)
	assert.Equal(t, `#!/bin/bash

echo "Preremove" > /dev/null
`, data, "Preremove script does not match")

	data, err = rpm.Header.GetString(tagPostin)
	assert.NoError(t, err)
	assert.Equal(t, `#!/bin/bash

echo "Postinstall" > /dev/null
`, data, "Postinstall script does not match")

	data, err = rpm.Header.GetString(tagPostun)
	assert.NoError(t, err)
	assert.Equal(t, `#!/bin/bash

echo "Postremove" > /dev/null
`, data, "Postremove script does not match")
}

func TestRPMNoFiles(t *testing.T) {
	info := exampleInfo()
	info.Files = map[string]string{}
	info.ConfigFiles = map[string]string{}
	var err = Default.Package(info, ioutil.Discard)
	// TODO: better deal with this error
	assert.Error(t, err)
}

func TestRPMFileDoesNotExist(t *testing.T) {
	info := exampleInfo()
	info.Files = map[string]string{
		"../testdata/": "/usr/local/bin/fake",
	}
	info.ConfigFiles = map[string]string{
		"../testdata/whatever.confzzz": "/etc/fake/fake.conf",
	}
	var err = Default.Package(info, ioutil.Discard)
	assert.EqualError(t, err, "../testdata/whatever.confzzz: file does not exist")
}

func TestRPMMultiArch(t *testing.T) {
	info := exampleInfo()

	for k := range archToRPM {
		info.Arch = k
		info = ensureValidArch(info)
		assert.Equal(t, archToRPM[k], info.Arch)
	}
}

func TestRPMSystemdUnitAndScripts(t *testing.T) {
	info := exampleInfo()

	info.SystemdUnits = []string{
		"../testdata/test.service",
	}

	f, err := ioutil.TempFile(".", fmt.Sprintf("%s-%s-*.rpm", info.Name, info.Version))
	defer func() {
		_ = f.Close()
		err = os.Remove(f.Name())
		assert.NoError(t, err)
	}()
	assert.NoError(t, err)
	err = Default.Package(info, f)
	assert.NoError(t, err)
	file, err := os.OpenFile(f.Name(), os.O_RDONLY, 0600) //nolint:gosec
	assert.NoError(t, err)
	rpm, err := rpmutils.ReadRpm(file)
	assert.NoError(t, err)

	scripts, err := exampleScripts(info)
	assert.NoError(t, err)

	var (
		preInstall  = strings.Join(scripts.PreInstall, "\n")
		preRemove   = strings.Join(scripts.PreRemove, "\n")
		postInstall = strings.Join(scripts.PostInstall, "\n")
		postRemove  = strings.Join(scripts.PostRemove, "\n")
	)

	data, err := rpm.Header.GetString(tagPrein)
	assert.NoError(t, err)
	assert.Equal(t, preInstall, data, "Preinstall script does not match")

	data, err = rpm.Header.GetString(tagPreun)
	assert.NoError(t, err)
	assert.Equal(t, preRemove, data, "Preremove script does not match")

	data, err = rpm.Header.GetString(tagPostin)
	assert.NoError(t, err)
	assert.Equal(t, postInstall, data, "Postinstall script does not match")

	data, err = rpm.Header.GetString(tagPostun)
	assert.NoError(t, err)
	assert.Equal(t, postRemove, data, "Postremove script does not match")
}
