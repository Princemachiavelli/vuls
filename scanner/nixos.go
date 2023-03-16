package scanner

import (
	"encoding/json"
	"regexp"
	"strings"
	"path/filepath"

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
func newNixOS(c config.ServerInfo) *nixos {
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

func detectNixOS(c config.ServerInfo) (bool, osTypeInterface, error) {
	if r := exec(c, "cat /etc/lsb-release", noSudo); r.isSuccess() {
		re := regexp.MustCompile(`.*DISTRIB_ID=(?P<distro>nixos)\nDISTRIB_RELEASE=\"(?P<version>.{5,10})\".*`)
		result := re.FindStringSubmatch(trim(r.Stdout))
		nixos := newNixOS(c)
		if len(result) == 0 {
			logging.Log.Warnf("Unknown NixOS: %s", r)
			nixos.setDistro(constant.NixOS, "unknown")
			return false, nixos, nil
		} else {
			nixos.setDistro(constant.NixOS, trim(result[2]))
			return true, nixos, nil
		}
	}
	return false, nil, nil
}

// nixos-upgrade.service
func(o *nixos) rebootRequired() (bool, error) {
	files := []string{"initrd", "kernel", "kernel-modules"}
	for _,f := range files {
		booted, err := filepath.EvalSymlinks("/run/booted-system/" + f)
		if err != nil {
			return false, err
		}
		built, err := filepath.EvalSymlinks("/nix/var/nix/profiles/system/" + f)
		if err != nil {
			return false, err
		}
		if booted != built {
			return true, nil
		}
	}
	return false, nil
}

func (o *nixos) checkScanMode() error {
	if o.getServerInfo().Mode.IsOffline() {
		return xerrors.New("Remove offline scan mode, NixOS needs internet connection")
	}
	return nil
}

func (o *nixos) checkDeps() error {
	o.log.Infof("Dependencies... No need")
	return nil
}

// Not sure if we need Sudo on NixOS
func (o *nixos) checkIfSudoNoPasswd() error {
	o.log.Infof("sudo ... No need")
	return nil
}

func (o *nixos) scanInstalledPackages() (models.Packages, error) {
	//cmd := util.PrependProxyEnv("nix-store -q --references /var/run/current-system/sw")
	cmd := util.PrependProxyEnv("nix-store --gc --print-live")
	r := o.exec(cmd, noSudo)
	if !r.isSuccess() {
		return nil, xerrors.Errorf("Failed to SSH: %s", r)
	}
	installed, _, err := o.parseInstalledPackages(r.Stdout)
	return installed, err
}

func (o *nixos) parseInstalledPackages(stdout string) (models.Packages, models.SrcPackages, error) {
	packs := models.Packages{}
	lines := strings.Split(stdout, "\n")
	ignoreExt := []string{".tar.gz", ".tar.bz2", ".tar.xz", ".tar.lz", ".tgz", ".zip", ".gem",
    ".patch", ".patch.gz", ".patch.xz", ".diff"}
	re := regexp.MustCompile(`^(\S+?)-(?P<name>\S+?)-(?P<version>[0-9]\S*)$`)
	for _, l := range lines {
		for _,e := range ignoreExt {
			if strings.HasSuffix(l, e) {
				continue
			} 
		}
		if strings.HasSuffix(l, ".drv"){
			l = l[:len(l)-4]
		}
		result := re.FindStringSubmatch(l)
		if len(result) < 3 {
			o.log.Infof("Failed to parse store path: %s", l)
			continue
		}
		//name := strings.ToLower(result[2])
		name := result[2]
		ver := result[3]
		packs[name] = models.Package{
			Name:    name,
			Version: ver,
		}
	}
	return packs, nil, nil
}

type auditResult struct {
	Name            string             `json:"name"`
	Pname           string             `json:"pname"`
	Version         string             `json:"version"`
	Derivation      string             `json:"derivation"`
	AffectedBy      []string           `json:"affected_by"`
	Whitelisted     []string           `json:"whitelisted"`
	Cvssv3Basescore map[string]float64 `json:"cvssv3_basescore"`
	Description     map[string]string  `json:"description"`
}

/*
type nixAuditResult struct {
	pack	models.Package
	auditResult auditResult
}
*/

type nixAuditResult struct {
	pack   models.Package
	cveIDs []string
}

func (o *nixos) parseVulnix(vulnixJson string) ([]auditResult, error) {
	data := []byte(vulnixJson)
	vulnixRslt := []auditResult{}
	err := json.Unmarshal(data, &vulnixRslt)
	if err != nil {
		return nil, xerrors.Errorf("Failed to parse vulnix JSON")
	}
	return vulnixRslt, nil
}

func (o *nixos) scanUnsecurePackages() (models.VulnInfos, error) {
	cmd := "vulnix --gc-roots --json"
	r := o.exec(cmd, noSudo)
	if !(r.ExitStatus == 2 || r.ExitStatus == 0) {
		return nil, xerrors.Errorf("Failed to SSH: %s", r)
	}
	if r.ExitStatus == 0 {
		// no vulnerabilities
		return nil, nil
	}

	vulnixRslt, err := o.parseVulnix(r.Stdout)
	if err != nil {
		o.log.Errorf("Failed to parse vulnix output: %s", err)
		return nil, err
	}

	vulnixRsltPkgs := []nixAuditResult{}
	for _, r := range vulnixRslt {
		if r.Pname == "" || len(r.AffectedBy) == 0 {
			o.log.Errorf("Unknown/incomplete package info %s", r.Name)
			continue
		}
		pack := models.Package{
			Name:    r.Pname,
			Version: r.Version,
		}
		vulnixRsltPkgs = append(vulnixRsltPkgs, nixAuditResult{
			pack:   pack,
			cveIDs: r.AffectedBy,
		})

	}

	cveIDAdtMap := make(map[string][]nixAuditResult)
	for _, p := range vulnixRsltPkgs {
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

func (o *nixos) postScan() error {
	return nil
}

func (o *nixos) preCure() error {
	if err := o.detectIPAddr(); err != nil {
		o.log.Warnf("Failed to detect IP addresses: %s", err)
		o.warns = append(o.warns, err)
	}
	// Ignore this error as it just failed to detect the IP addresses
	return nil
}

func (o *nixos) detectIPAddr() (err error) {
	o.ServerInfo.IPv4Addrs, o.ServerInfo.IPv6Addrs, err = o.ip()
	return err
}

// ip executes ip command and returns IP addresses
func (o *nixos) ip() ([]string, []string, error) {
	// e.g.
	// 2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000\    link/ether 52:54:00:2a:86:4c brd ff:ff:ff:ff:ff:ff
	// 2: eth0    inet 10.0.2.15/24 brd 10.0.2.255 scope global eth0
	// 2: eth0    inet6 fe80::5054:ff:fe2a:864c/64 scope link \       valid_lft forever preferred_lft forever
	r := o.exec("ip -o addr", noSudo)
	if !r.isSuccess() {
		return nil, nil, xerrors.Errorf("Failed to detect IP address: %v", r)
	}
	ipv4Addrs, ipv6Addrs := o.parseIP(r.Stdout)
	return ipv4Addrs, ipv6Addrs, nil
}

func (o *nixos) scanPackages() error {
	o.log.Infof("Scanning OS pkg in %s", o.getServerInfo().Mode)
	// collect the running kernel information
	release, version, err := o.runningKernel()
	if err != nil {
		o.log.Errorf("Failed to scan the running kernel version: %s", err)
		return err
	}
	o.Kernel = models.Kernel{
		Release: release,
		Version: version,
	}

	//TODO: check if reboot is required
	o.Kernel.RebootRequired, err = o.rebootRequired()
	if err != nil {
		o.log.Errorf("Failed to check if reboot is required: %s", err)
		return err
	}

	// Installed Packages
	installed, err := o.scanInstalledPackages()
	if err != nil {
		o.log.Errorf("Failed to scan installed packages: %s", err)
		return err
	}
	o.Packages = installed
	// Unsecure Packages
	unsecures, err := o.scanUnsecurePackages()
	if err != nil {
		o.log.Errorf("Failed to scan vulnerable packages: %s", err)
		return err
	}
	o.VulnInfos = unsecures

	return nil
}
