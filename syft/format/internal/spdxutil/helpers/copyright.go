package helpers

import "github.com/anchore/syft/syft/pkg"

// Copyright extracts copyright text from package metadata.
// For PE binaries, it returns the LegalCopyright field from version resources.
// Returns NOASSERTION if no copyright information is available.
func Copyright(p pkg.Package) string {
	if hasMetadata(p) {
		switch metadata := p.Metadata.(type) {
		case pkg.PEBinary:
			if copyright, ok := metadata.VersionResources.Get("LegalCopyright"); ok && copyright != "" {
				return copyright
			}
		}
	}
	return NOASSERTION
}
