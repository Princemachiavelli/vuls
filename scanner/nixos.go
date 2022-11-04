package scanner

import (
	"bufio"
	"strings"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/constant"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
	"golang.org/x/xerrors"
)

// inherit OsTypeInterface
type nixos struct {
	base
}

// NewAlpine is constructor
func newNixOS(c config.ServerInfo) *nixos{
	d := &nixos{
		base: base{
			osPackages: osPackages{
				Packages:  models.Packages{},
				VulnInfos: models.VulnInfos{},
			},
		},
	}
	d.log = logging.NewNormalLogger()
	d.setServerInfo(c)
	return d
}

func detectNixOS(c config.ServerInfo) (bool, osTypeInterface) {
	if r := exec(c, "cat /etc/lsb-release", noSudo); r.isSuccess() {
		re := regexp.MustCompile(`(?s)^DISTRIB_ID=nixos\n*DISTRIB_RELEASE=(.+?)\n.*$`)
		result := re.FindStringSubmatch(trim(r.Stdout))
		if len(result) == 0 {
			return false, nil, nil
		} else {
			distro := "nixos"
			deb.setDistro(distro, trim(result[2]))
		}
	}
	nix := newNixOS(c)
}

func (o *nixos) checkScanMode() error {
	if o.getServerInfo().Mode.IsOffline() {
		return xerrors.New("Remove offline scan mode, NixOS needs internet connection")
	}
	return nil
}

func (o *nixos) scanInstalledPackages() (models.Packages, error) {
	cmd := util.PrependProxyEnv("nix-store -q --references /var/run/current-system/sw")
	r := o.exec(cmd, noSudo)
	if !r.isSuccess() {
		return nil, xerrors.Errorf("Failed to SSH: %s", r)
	}
	return o.parseInstalledPackages(r.Stdout)
}

func (o *nixos) parseInstalledPackages(stdout string) (models.Packages, models.SrcPackages, error) {
	packs := models.Packages{}
	lines := strings.Split(stdout, "\n")
	for _, l := range lines {
		fields := strings.Split(l, '-')
		if len(fields) < 2 {
			return nil, xerrors.Errorf("Failed to parse nix packages: %s", line)
		}

		name := fields[1]
		ver := strings.Join(ss[:len(ss)-3], "-")
		packs[name] = models.Package{
			Name:    name,
			Version: ver,
		}
	}
	return packs, nil
}

type auditResult struct {
	Name            string        `json:"name"`
	Pname           string        `json:"pname"`
	Version         string        `json:"version"`
	Derivation      string        `json:"derivation"`
	AffectedBy      []string      `json:"affected_by"`
	Whitelisted     []interface{} `json:"whitelisted"`
	Cvssv3Basescore map[string]string      `json:"cvssv3_basescore"`
	Description     map[string]string      `json:"description"`
}

type pkgAuditResult struct {
	pack	models.Package
	auditResult auditResult
}



type pkgAuditResult struct {
	pack	models.Package
	cveIDs	[]string     
}

func (o *nixos) scanUnsecurePackages() (models.VulnInfos, error) {
	cmd := "vulnix --gc-roots --json"
	r := o.exec(cmd, noSudo)
	if !r.isSuccess(0) {
		return nil, xerrors.Errorf("Failed to SSH: %s", r)
	}
	if r.ExitStatus == 0 {
		// no vulnerabilities
		return nil, nil
	}

	vulnixRslt = parseVulnix(r.Stdout)

	vulnixRsltPkgs := []pkgAuditResult{}
	for _, r := range vulnixRslt {
		name := r.Pname
		cveIDs := r.AffectedBy
		if name == "" || len(cveIDs) == 0 {
			continue
		}
		// not sure if o.Packages will have all the packagse from all GC roots
		pack, found := o.Packages[name]
		if !found {
			return nil, xerrors.Errorf("Vulnerable package: %s is not found", name)
		}
		vulnixRsltPkgs = append(vulnixRsltPkgs, pkgAuditResult {
			pack: pack,
			cveIDs: cveIDs
		})

	}


	cveIDAdtMap := make(map[string][]pkgAuditResult)
	for _, p := range vulnixRslt {
		for _, cid := range p.cveIDs {
			cveIDAdtMap[cid] = append(cveIDAdtMap[cid], p)
		}
	}
	
	vinfos := models.VulnInfos{}
	for cveID := range cveIDAdtMap {
		packs := models.Packages{}
		for _, r := range cveIDAdtMap[cveID] {
			packs[r.pack.Name] = r.pack
		}

		affected := models.PackageFixStatuses{}
		for name := range packs {
			affected = append(affected, models.PackageFixStatus{
				Name: name,
			})
		}
		vinfos[cveID] = models.VulnInfo{
			CveID:            cveID,
			AffectedPackages: affected,
			Confidences:      models.Confidences{models.PkgAuditMatch},
		}
	}
	return vinfos, nil

}

func (o *nixos) parseVulnix(string i) ([]auditResult{}){
	data := []byte(i)
	vulnixRslt := []auditResult{}
	err := json.Unmarshal(data, &vulnixRslt)
	if err != nil {
		return nil, xerrors.Errorf("Failed to parse vulnix JSON")
	}
	return vulnixRslt
}
