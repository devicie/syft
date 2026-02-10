package helpers

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/pkg"
)

func TestCopyright(t *testing.T) {
	tests := []struct {
		name     string
		pkg      pkg.Package
		expected string
	}{
		{
			name: "PE binary with LegalCopyright",
			pkg: pkg.Package{
				Name: "test",
				Metadata: pkg.PEBinary{
					VersionResources: pkg.KeyValues{
						{Key: "LegalCopyright", Value: "Copyright (c) 2024 Test Company"},
						{Key: "ProductName", Value: "Test Product"},
					},
				},
			},
			expected: "Copyright (c) 2024 Test Company",
		},
		{
			name: "PE binary without LegalCopyright",
			pkg: pkg.Package{
				Name: "test",
				Metadata: pkg.PEBinary{
					VersionResources: pkg.KeyValues{
						{Key: "ProductName", Value: "Test Product"},
					},
				},
			},
			expected: NOASSERTION,
		},
		{
			name: "PE binary with empty LegalCopyright",
			pkg: pkg.Package{
				Name: "test",
				Metadata: pkg.PEBinary{
					VersionResources: pkg.KeyValues{
						{Key: "LegalCopyright", Value: ""},
						{Key: "ProductName", Value: "Test Product"},
					},
				},
			},
			expected: NOASSERTION,
		},
		{
			name: "non-PE binary package",
			pkg: pkg.Package{
				Name: "test",
				Metadata: pkg.NpmPackage{
					Name: "test-package",
				},
			},
			expected: NOASSERTION,
		},
		{
			name: "package with no metadata",
			pkg: pkg.Package{
				Name: "test",
			},
			expected: NOASSERTION,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Copyright(tt.pkg)
			assert.Equal(t, tt.expected, result)
		})
	}
}
