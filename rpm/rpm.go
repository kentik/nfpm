// Package rpm implements nfpm.Packager providing .rpm bindings using
// google/rpmpack.
package rpm

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/rpmpack"
	"github.com/pkg/errors"

	"github.com/goreleaser/nfpm"
	"github.com/goreleaser/nfpm/glob"
)

// nolint: gochecknoinits
func init() {
	nfpm.Register("rpm", Default)
}

// Default RPM packager
// nolint: gochecknoglobals
var Default = &RPM{}

// RPM is a RPM packager implementation.
type RPM struct{}

type Scripts struct {
	PreInstall  []string
	PostInstall []string
	PreRemove   []string
	PostRemove  []string
}

// nolint: gochecknoglobals
var archToRPM = map[string]string{
	"amd64": "x86_64",
	"386":   "i386",
	"arm64": "aarch64",
}

func ensureValidArch(info *nfpm.Info) *nfpm.Info {
	arch, ok := archToRPM[info.Arch]
	if ok {
		info.Arch = arch
	}
	return info
}

// Package writes a new RPM package to the given writer using the given info.
func (*RPM) Package(info *nfpm.Info, w io.Writer) error {
	var (
		err     error
		meta    *rpmpack.RPMMetaData
		rpm     *rpmpack.RPM
		scripts *Scripts
	)
	info = ensureValidArch(info)
	if err = nfpm.Validate(info); err != nil {
		return err
	}

	if scripts, err = loadScripts(info); err != nil {
		return err
	}

	if meta, err = buildRPMMeta(info); err != nil {
		return err
	}
	if rpm, err = rpmpack.NewRPM(*meta); err != nil {
		return err
	}

	addEmptyDirsRPM(info, rpm)
	if err = createFilesInsideRPM(info, rpm); err != nil {
		return err
	}

	if err = addScripts(info, rpm, scripts); err != nil {
		return err
	}

	if err = addSystemdUnits(info, rpm); err != nil {
		return err
	}

	if err = addUser(info, rpm); err != nil {
		return err
	}

	if err = rpm.Write(w); err != nil {
		return err
	}

	return nil
}

func buildRPMMeta(info *nfpm.Info) (*rpmpack.RPMMetaData, error) {
	var (
		err   error
		epoch uint64
		provides,
		depends,
		replaces,
		suggests,
		conflicts rpmpack.Relations
	)
	if epoch, err = strconv.ParseUint(defaultTo(info.Epoch, "0"), 10, 32); err != nil {
		return nil, err
	}
	if provides, err = toRelation(info.Provides); err != nil {
		return nil, err
	}
	if depends, err = toRelation(info.Depends); err != nil {
		return nil, err
	}
	if replaces, err = toRelation(info.Replaces); err != nil {
		return nil, err
	}
	if suggests, err = toRelation(info.Suggests); err != nil {
		return nil, err
	}
	if conflicts, err = toRelation(info.Conflicts); err != nil {
		return nil, err
	}

	hostname, err := os.Hostname()
	if err != nil {
		return nil, err
	}

	return &rpmpack.RPMMetaData{
		Name:        info.Name,
		Summary:     strings.Split(info.Description, "\n")[0],
		Description: info.Description,
		Version:     info.Version,
		Release:     releaseFor(info),
		Epoch:       uint32(epoch),
		Arch:        info.Arch,
		OS:          info.Platform,
		Licence:     info.License,
		URL:         info.Homepage,
		Vendor:      info.Vendor,
		Packager:    info.Maintainer,
		Group:       defaultTo(info.RPM.Group, "Development/Tools"),
		Provides:    provides,
		Requires:    depends,
		Obsoletes:   replaces,
		Suggests:    suggests,
		Conflicts:   conflicts,
		Compressor:  info.RPM.Compression,
		BuildTime:   time.Now(),
		BuildHost:   hostname,
	}, nil
}

func releaseFor(info *nfpm.Info) string {
	var release = defaultTo(info.Release, "1")
	if info.Prerelease != "" {
		release = fmt.Sprintf("%s.%s", defaultTo(info.Release, "0.1"), info.Prerelease)
	}
	return release
}

func defaultTo(in, def string) string {
	if in == "" {
		return def
	}
	return in
}

func toRelation(items []string) (rpmpack.Relations, error) {
	relations := make(rpmpack.Relations, 0)
	for idx := range items {
		if err := relations.Set(items[idx]); err != nil {
			return nil, err
		}
	}

	return relations, nil
}

func loadScripts(info *nfpm.Info) (*Scripts, error) {
	scripts := &Scripts{}

	for _, systemdUnit := range info.SystemdUnits {
		unit := filepath.Base(systemdUnit)
		scripts.PostInstall = append(scripts.PostInstall,
			strings.ReplaceAll(scriptSystemdPostinst, "%{package_unit}", unit))
		scripts.PreRemove = append(scripts.PreRemove,
			strings.ReplaceAll(scriptSystemdPreun, "%{package_unit}", unit))
		scripts.PostRemove = append(scripts.PostRemove,
			strings.ReplaceAll(scriptSystemdPostun, "%{package_unit}", unit))
	}

	if info.Scripts.PreInstall != "" {
		data, err := ioutil.ReadFile(info.Scripts.PreInstall)
		if err != nil {
			return nil, err
		}
		scripts.PreInstall = append(scripts.PreInstall, string(data))
	}

	if info.Scripts.PreRemove != "" {
		data, err := ioutil.ReadFile(info.Scripts.PreRemove)
		if err != nil {
			return nil, err
		}
		scripts.PreRemove = append(scripts.PreRemove, string(data))
	}

	if info.Scripts.PostInstall != "" {
		data, err := ioutil.ReadFile(info.Scripts.PostInstall)
		if err != nil {
			return nil, err
		}
		scripts.PostInstall = append(scripts.PostInstall, string(data))
	}

	if info.Scripts.PostRemove != "" {
		data, err := ioutil.ReadFile(info.Scripts.PostRemove)
		if err != nil {
			return nil, err
		}
		scripts.PostRemove = append(scripts.PostRemove, string(data))
	}

	return scripts, nil
}

func addScripts(info *nfpm.Info, rpm *rpmpack.RPM, scripts *Scripts) error {
	if len(scripts.PreInstall) > 0 {
		rpm.AddPrein(strings.Join(scripts.PreInstall, "\n"))
	}

	if len(scripts.PreRemove) > 0 {
		rpm.AddPreun(strings.Join(scripts.PreRemove, "\n"))
	}

	if len(scripts.PostInstall) > 0 {
		rpm.AddPostin(strings.Join(scripts.PostInstall, "\n"))
	}

	if len(scripts.PostRemove) > 0 {
		rpm.AddPostun(strings.Join(scripts.PostRemove, "\n"))
	}

	return nil
}

func addSystemdUnits(info *nfpm.Info, rpm *rpmpack.RPM) error {
	if len(info.SystemdUnits) > 0 {
		for _, systemdUnit := range info.SystemdUnits {
			unit := filepath.Base(systemdUnit)
			dst := filepath.Join("/lib/systemd/system/", unit)
			err := copyToRPM(rpm, systemdUnit, dst, false, "root")
			if err != nil {
				return err
			}
		}
		// TODO: it would be much better to use `Requires(pre):`, etc...,
		// but the option is missing from rpmpack public api
		info.Depends = append(info.Depends, "systemd")
	}
	return nil
}

func addUser(info *nfpm.Info, rpm *rpmpack.RPM) error {
	if info.User != "" {
		rpm.AddPrein(strings.ReplaceAll(scriptCreateUser, "%{package_user}", info.User))
	}

	return nil
}

func addEmptyDirsRPM(info *nfpm.Info, rpm *rpmpack.RPM) {
	for _, dir := range info.EmptyFolders {
		rpm.AddFile(
			rpmpack.RPMFile{
				Name:  dir,
				Mode:  uint(040755),
				MTime: uint32(time.Now().Unix()),
				Owner: info.User,
				Group: info.User,
			},
		)
	}
}

func createFilesInsideRPM(info *nfpm.Info, rpm *rpmpack.RPM) error {
	copyFunc := func(files map[string]string, config bool) error {
		for srcglob, dstraw := range files {
			dstroot, user, _ := getFilesAttr(dstraw)
			if user == "" {
				user = info.User
			}
			globbed, err := glob.Glob(srcglob, dstroot)
			if err != nil {
				return err
			}
			for src, dst := range globbed {
				// when used as a lib, target may not be set.
				// in that case, src will always have the empty sufix, and all
				// files will be ignored.
				if info.Target != "" && strings.HasSuffix(src, info.Target) {
					fmt.Printf("skipping %s because it has the suffix %s", src, info.Target)
					continue
				}
				err := copyToRPM(rpm, src, dst, config, user)
				if err != nil {
					return err
				}
			}
		}

		return nil
	}

	err := copyFunc(info.Files, false)
	if err != nil {
		return err
	}

	err = copyFunc(info.ConfigFiles, true)
	if err != nil {
		return err
	}

	return nil
}

func copyToRPM(rpm *rpmpack.RPM, src, dst string, config bool, user string) error {
	file, err := os.OpenFile(src, os.O_RDONLY, 0600) //nolint:gosec
	if err != nil {
		return errors.Wrap(err, "could not add file to the archive")
	}
	// don't care if it errs while closing...
	defer file.Close() // nolint: errcheck,gosec
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if info.IsDir() {
		// TODO: this should probably return an error
		return nil
	}
	data, err := ioutil.ReadAll(file)
	if err != nil {
		return err
	}

	rpmFile := rpmpack.RPMFile{
		Name:  dst,
		Body:  data,
		Mode:  uint(info.Mode()),
		MTime: uint32(info.ModTime().Unix()),
		Owner: user,
		Group: user,
	}

	if config {
		rpmFile.Type = rpmpack.ConfigFile
	}

	rpm.AddFile(rpmFile)

	return nil
}

func getFilesAttr(raw string) (name, user, mode string) {
	parts := strings.Split(raw, ":")
	name, user, mode = raw, "", ""
	if len(parts) > 0 {
		name = parts[0]
	}
	if len(parts) > 1 {
		user = parts[1]
	}
	if len(parts) > 2 {
		mode = parts[2]
	}

	return name, user, mode
}
