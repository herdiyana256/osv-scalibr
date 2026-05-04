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

// Package wolfi extracts packages from Wolfi OS and Chainguard APK databases.
//
// Wolfi is a Linux-based OS designed by Chainguard for containers. Wolfi and
// Chainguard images use the standard APK database format (shared with Alpine
// Linux), but their packages are tracked in separate OSV.dev ecosystems:
// "Wolfi" and "Chainguard". This extractor handles those images specifically,
// emitting inventory with the correct purl namespace so that OSV-SCALIBR can
// match vulnerabilities from those ecosystems.
//
// Detection: reads /etc/os-release and only activates when ID=wolfi or
// ID=chainguard. If neither matches, this extractor yields no results,
// leaving the os/apk extractor to handle other APK-based systems (Alpine, etc).
package wolfi

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/os/apk/apkutil"
	apkmeta "github.com/google/osv-scalibr/extractor/filesystem/os/apk/metadata"
	"github.com/google/osv-scalibr/extractor/filesystem/os/osrelease"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
)

const (
	// Name is the unique name of this extractor.
	Name = "os/wolfi"

	// noLimitMaxFileSizeBytes is a sentinel value indicating no file size limit.
	noLimitMaxFileSizeBytes = int64(0)
)

// Extractor extracts packages from Wolfi OS and Chainguard container image APK
// databases.
type Extractor struct {
	Stats            stats.Collector
	maxFileSizeBytes int64
}

// New returns a Wolfi/Chainguard APK extractor.
//
// For most use cases, initialize with:
//
//	e := New(&cpb.PluginConfig{})
func New(cfg *cpb.PluginConfig) (filesystem.Extractor, error) {
	maxFileSizeBytes := noLimitMaxFileSizeBytes
	if cfg.GetMaxFileSizeBytes() > 0 {
		maxFileSizeBytes = cfg.GetMaxFileSizeBytes()
	}
	return &Extractor{maxFileSizeBytes: maxFileSizeBytes}, nil
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired returns true if the specified file matches the APK database path.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := filepath.ToSlash(api.Path())
	if path != "lib/apk/db/installed" &&
		path != "var/lib/apk/db/installed" &&
		// TODO(b/428271704): Remove once we handle symlinks properly.
		path != "usr/lib/apk/db/installed" {
		return false
	}

	fileinfo, err := api.Stat()
	if err != nil {
		return false
	}
	if e.maxFileSizeBytes > noLimitMaxFileSizeBytes && fileinfo.Size() > e.maxFileSizeBytes {
		e.reportFileRequired(api.Path(), fileinfo.Size(), stats.FileRequiredResultSizeLimitExceeded)
		return false
	}

	e.reportFileRequired(api.Path(), fileinfo.Size(), stats.FileRequiredResultOK)
	return true
}

func (e Extractor) reportFileRequired(path string, fileSizeBytes int64, result stats.FileRequiredResult) {
	if e.Stats == nil {
		return
	}
	e.Stats.AfterFileRequired(e.Name(), &stats.FileRequiredStats{
		Path:          path,
		Result:        result,
		FileSizeBytes: fileSizeBytes,
	})
}

// Extract extracts packages from the APK database on Wolfi/Chainguard systems.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	pkgs, err := e.extractFromInput(ctx, input)
	if e.Stats != nil {
		var fileSizeBytes int64
		if input.Info != nil {
			fileSizeBytes = input.Info.Size()
		}
		e.Stats.AfterFileExtracted(e.Name(), &stats.FileExtractedStats{
			Path:          input.Path,
			Result:        filesystem.ExtractorErrorToFileExtractedResult(err),
			FileSizeBytes: fileSizeBytes,
		})
	}
	return inventory.Inventory{Packages: pkgs}, err
}

// isWolfiOrChainguard reports whether the OS release map indicates a Wolfi or
// Chainguard system. It checks both the ID field and PRETTY_NAME to handle
// different image configurations.
func isWolfiOrChainguard(m map[string]string) bool {
	id := strings.ToLower(m["ID"])
	if id == "wolfi" || id == "chainguard" {
		return true
	}
	// Some Chainguard images may not set ID=chainguard but include "Chainguard"
	// in their PRETTY_NAME.
	prettyName := strings.ToLower(m["PRETTY_NAME"])
	return strings.Contains(prettyName, "chainguard")
}

func (e Extractor) extractFromInput(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Package, error) {
	m, err := osrelease.GetOSRelease(input.FS)
	if err != nil {
		log.Errorf("osrelease.GetOSRelease(): %v", err)
	}

	// Only extract on Wolfi/Chainguard systems. Other APK-based systems (e.g.
	// Alpine, OpenWRT) are handled by the os/apk extractor.
	if !isWolfiOrChainguard(m) {
		return nil, nil
	}

	scanner := apkutil.NewScanner(input.Reader)
	packages := []*extractor.Package{}

	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("%s halted due to context error: %w", e.Name(), err)
		}

		record := scanner.Record()

		var sourceCode *extractor.SourceCodeIdentifier
		if commit, ok := record["c"]; ok {
			sourceCode = &extractor.SourceCodeIdentifier{
				Commit: commit,
			}
		}

		pkg := &extractor.Package{
			Name:     record["P"],
			Version:  record["V"],
			PURLType: purl.TypeApk,
			Metadata: &apkmeta.Metadata{
				OSID:         m["ID"],
				OSVersionID:  m["VERSION_ID"],
				PackageName:  record["P"],
				OriginName:   record["o"],
				Architecture: record["A"],
				Maintainer:   record["m"],
			},
			Licenses:   []string{record["L"]},
			SourceCode: sourceCode,
			Location:   extractor.LocationFromPath(input.Path),
		}

		if pkg.Name == "" || pkg.Version == "" {
			log.Warnf("Wolfi package name or version is empty (name: %q, version: %q)", pkg.Name, pkg.Version)
			continue
		}

		packages = append(packages, pkg)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error while parsing APK status file: %w", err)
	}

	return packages, nil
}
