package scanner

import (
	"reflect"
	"testing"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
)

func TestParseVulnixJSON(t *testing.T) {
	var tests = []struct {
		in    string
		packs models.Packages
	}{
		{
			in: `
[
 {
  "name": "Nuget-5.6.0.6489",
  "pname": "Nuget",
  "version": "5.6.0.6489",
  "derivation": "/nix/store/lhn0ziasnffvlcqnmsk3jdnqfvpy8rwg-Nuget-5.6.0.6489.drv",
  "affected_by": [
   "CVE-2022-30184"
  ],
  "whitelisted": [],
  "cvssv3_basescore": {
   "CVE-2022-30184": 5.5
  },
  "description": {
   "CVE-2022-30184": ".NET and Visual Studio Information Disclosure Vulnerability."
  }
 },
 {
  "name": "SDL_ttf-2.0.11",
  "pname": "SDL_ttf",
  "version": "2.0.11",
  "derivation": "/nix/store/y2pzzzp4qyhsm3rkhww1mbchm2641p1c-SDL_ttf-2.0.11.drv",
  "affected_by": [
   "CVE-2022-27470"
  ],
  "whitelisted": [],
  "cvssv3_basescore": {
   "CVE-2022-27470": 7.8
  },
  "description": {
   "CVE-2022-27470": "SDL_ttf v2.0.18 and below was discovered to contain an arbitrary memory write via the function TTF_RenderText_Solid(). This vulnerability is triggered via a crafted TTF file."
  }
 }
]`,
			packs: models.Packages{
				"Nuget": {
					Name:    "Nuget",
					Version: "5.6.0.6489",
				},
				"SDL_ttf": {
					Name:	"SDL_ttf",
					Version: "2.0.11",
				},
			},
		},
	}
	d := newNixOS(config.ServerInfo{})
	for i, tt := range tests {
		pkgs, _ := d.parseVulnix(tt.in)
		if !reflect.DeepEqual(tt.packs, pkgs) {
			t.Errorf("[%d] expected %v, actual %v", i, tt.packs, pkgs)
		}
	}
}

// test nix-store -q --references /$profile_path
func TestParseNixOSPackages(t *testing.T) {}
