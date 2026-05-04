// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package wolfi_test

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	apkmeta "github.com/google/osv-scalibr/extractor/filesystem/os/apk/metadata"
	"github.com/google/osv-scalibr/extractor/filesystem/os/wolfi"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
	"github.com/google/osv-scalibr/testing/fakefs"
	"github.com/google/osv-scalibr/testing/testcollector"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

func TestFileRequired(t *testing.T) {
	tests := []struct {
		name             string
		path             string
		fileSizeBytes    int64
		maxFileSizeBytes int64
		wantRequired     bool
		wantResultMetric stats.FileRequiredResult
	}{
		{
			name:             "installed file in /lib",
			path:             "lib/apk/db/installed",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "installed file in /var",
			path:             "var/lib/apk/db/installed",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "installed file in /usr",
			path:             "usr/lib/apk/db/installed",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:         "unrelated file",
			path:         "etc/os-release",
			wantRequired: false,
		},
		{
			name:         "inside other dir",
			path:         "foo/lib/apk/db/installed",
			wantRequired: false,
		},
		{
			name:             "file size below limit",
			path:             "var/lib/apk/db/installed",
			fileSizeBytes:    100 * units.KiB,
			maxFileSizeBytes: 1000 * units.KiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "file size at limit",
			path:             "var/lib/apk/db/installed",
			fileSizeBytes:    100 * units.KiB,
			maxFileSizeBytes: 100 * units.KiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "file size above limit",
			path:             "var/lib/apk/db/installed",
			fileSizeBytes:    1000 * units.KiB,
			maxFileSizeBytes: 100 * units.KiB,
			wantRequired:     false,
			wantResultMetric: stats.FileRequiredResultSizeLimitExceeded,
		},
		{
			name:             "no size limit when maxFileSizeBytes is 0",
			path:             "var/lib/apk/db/installed",
			fileSizeBytes:    100 * units.KiB,
			maxFileSizeBytes: 0,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collector := testcollector.New()
			e, err := wolfi.New(&cpb.PluginConfig{MaxFileSizeBytes: tt.maxFileSizeBytes})
			if err != nil {
				t.Fatalf("wolfi.New: %v", err)
			}
			e.(*wolfi.Extractor).Stats = collector

			fileSizeBytes := tt.fileSizeBytes
			if fileSizeBytes == 0 {
				fileSizeBytes = 1000
			}

			isRequired := e.FileRequired(simplefileapi.New(tt.path, fakefs.FakeFileInfo{
				FileName: filepath.Base(tt.path),
				FileMode: fs.ModePerm,
				FileSize: fileSizeBytes,
			}))
			if isRequired != tt.wantRequired {
				t.Fatalf("FileRequired(%s): got %v, want %v", tt.path, isRequired, tt.wantRequired)
			}

			gotResultMetric := collector.FileRequiredResult(tt.path)
			if tt.wantResultMetric != "" && gotResultMetric != tt.wantResultMetric {
				t.Errorf("FileRequired(%s) recorded result metric %v, want result metric %v", tt.path, gotResultMetric, tt.wantResultMetric)
			}
		})
	}
}

// os-release content for test cases.
const wolfiOSRelease = `NAME="Wolfi"
ID=wolfi
VERSION_ID=20230201
PRETTY_NAME="Wolfi"
HOME_URL="https://wolfi.dev"`

const chainguardOSRelease = `NAME="Chainguard"
ID=chainguard
VERSION_ID=20231201
PRETTY_NAME="Chainguard"
HOME_URL="https://chainguard.dev"`

const chainguardPrettyNameOnlyOSRelease = `NAME="Linux"
ID=linux
PRETTY_NAME="Chainguard Base Image"`

const alpineOSRelease = `NAME="Alpine Linux"
ID=alpine
VERSION_ID=3.18.0
PRETTY_NAME="Alpine Linux v3.18"
HOME_URL="https://alpinelinux.org/"`

func TestExtract(t *testing.T) {
	tests := []struct {
		name             string
		path             string
		osrelease        string
		wantPackages     []*extractor.Package
		wantErr          error
		wantResultMetric stats.FileExtractedResult
	}{
		{
			name:      "wolfi image",
			path:      "testdata/wolfi-installed",
			osrelease: wolfiOSRelease,
			wantPackages: []*extractor.Package{
				makePackage("testdata/wolfi-installed", "wolfi-baselayout", "wolfi-baselayout", "1.0.0-r2", "wolfi", "20230201", "Wolfi Maintainers <opensource@chainguard.dev>", "Apache-2.0", "aabbccdd11223344aabbccdd11223344aabbccdd"),
				makePackage("testdata/wolfi-installed", "python-3.11", "python-3.11", "3.11.7-r0", "wolfi", "20230201", "Wolfi Maintainers <opensource@chainguard.dev>", "PSF-2.0", "11223344aabbccdd11223344aabbccdd11223344"),
				makePackage("testdata/wolfi-installed", "openssl", "openssl", "3.1.4-r1", "wolfi", "20230201", "Wolfi Maintainers <opensource@chainguard.dev>", "Apache-2.0", "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:      "chainguard image (ID=chainguard)",
			path:      "testdata/chainguard-installed",
			osrelease: chainguardOSRelease,
			wantPackages: []*extractor.Package{
				makePackage("testdata/chainguard-installed", "chainguard-baselayout", "chainguard-baselayout", "1.0.0-r5", "chainguard", "20231201", "Chainguard <support@chainguard.dev>", "Apache-2.0", "cafebabecafebabecafebabecafebabecafebabe"),
				makePackage("testdata/chainguard-installed", "glibc", "glibc", "2.38-r5", "chainguard", "20231201", "Chainguard <support@chainguard.dev>", "LGPL-2.1-or-later", "feedfacedeadfeedfacedeadfeedfacedeadfeed"),
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:      "chainguard image (PRETTY_NAME contains Chainguard)",
			path:      "testdata/chainguard-installed",
			osrelease: chainguardPrettyNameOnlyOSRelease,
			wantPackages: []*extractor.Package{
				makePackage("testdata/chainguard-installed", "chainguard-baselayout", "chainguard-baselayout", "1.0.0-r5", "linux", "", "Chainguard <support@chainguard.dev>", "Apache-2.0", "cafebabecafebabecafebabecafebabecafebabe"),
				makePackage("testdata/chainguard-installed", "glibc", "glibc", "2.38-r5", "linux", "", "Chainguard <support@chainguard.dev>", "LGPL-2.1-or-later", "feedfacedeadfeedfacedeadfeedfacedeadfeed"),
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:             "alpine image is skipped",
			path:             "testdata/wolfi-installed",
			osrelease:        alpineOSRelease,
			wantPackages:     nil,
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:             "no os-release is skipped",
			path:             "testdata/wolfi-installed",
			osrelease:        "",
			wantPackages:     nil,
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:             "empty APK database",
			path:             "testdata/empty",
			osrelease:        wolfiOSRelease,
			wantPackages:     []*extractor.Package{},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collector := testcollector.New()
			e, err := wolfi.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("wolfi.New: %v", err)
			}
			e.(*wolfi.Extractor).Stats = collector

			d := t.TempDir()
			createOsRelease(t, d, tt.osrelease)

			r, err := os.Open(tt.path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err = r.Close(); err != nil {
					t.Errorf("Close(): %v", err)
				}
			}()

			info, err := os.Stat(tt.path)
			if err != nil {
				t.Fatalf("Failed to stat test file: %v", err)
			}

			input := &filesystem.ScanInput{
				FS:     scalibrfs.DirFS(d),
				Path:   tt.path,
				Reader: r,
				Root:   d,
				Info:   info,
			}

			got, err := e.Extract(t.Context(), input)
			if !cmp.Equal(err, tt.wantErr, cmpopts.EquateErrors()) {
				t.Fatalf("Extract(%+v) error: got %v, want %v\n", tt.name, err, tt.wantErr)
			}

			ignoreOrder := cmpopts.SortSlices(func(a, b any) bool {
				return fmt.Sprintf("%+v", a) < fmt.Sprintf("%+v", b)
			})
			wantInv := inventory.Inventory{Packages: tt.wantPackages}
			if diff := cmp.Diff(wantInv, got, ignoreOrder); diff != "" {
				t.Errorf("Extract(%s) (-want +got):\n%s", tt.path, diff)
			}

			gotResultMetric := collector.FileExtractedResult(tt.path)
			if tt.wantResultMetric != "" && gotResultMetric != tt.wantResultMetric {
				t.Errorf("Extract(%s) recorded result metric %v, want result metric %v", tt.path, gotResultMetric, tt.wantResultMetric)
			}

			gotFileSizeMetric := collector.FileExtractedFileSize(tt.path)
			if gotFileSizeMetric != info.Size() {
				t.Errorf("Extract(%s) recorded file size %v, want file size %v", tt.path, gotFileSizeMetric, info.Size())
			}
		})
	}
}

// makePackage is a test helper that constructs an expected extractor.Package.
func makePackage(path, pkgName, origin, version, osID, osVersionID, maintainer, license, commit string) *extractor.Package {
	p := &extractor.Package{
		Location: extractor.LocationFromPath(path),
		Name:     pkgName,
		Version:  version,
		PURLType: purl.TypeApk,
		Metadata: &apkmeta.Metadata{
			PackageName:  pkgName,
			OriginName:   origin,
			OSID:         osID,
			OSVersionID:  osVersionID,
			Maintainer:   maintainer,
			Architecture: "x86_64",
		},
		Licenses: []string{license},
	}
	if commit != "" {
		p.SourceCode = &extractor.SourceCodeIdentifier{
			Commit: commit,
		}
	}
	return p
}

// createOsRelease writes an /etc/os-release file in the given temp dir.
func createOsRelease(t *testing.T, root string, content string) {
	t.Helper()
	_ = os.MkdirAll(filepath.Join(root, "etc"), 0755)
	err := os.WriteFile(filepath.Join(root, "etc/os-release"), []byte(content), 0644)
	if err != nil {
		t.Fatalf("write to %s: %v\n", filepath.Join(root, "etc/os-release"), err)
	}
}
