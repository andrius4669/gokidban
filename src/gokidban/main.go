package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path"
	"sort"
	"strconv"

	"github.com/BurntSushi/toml"
	"github.com/oschwald/geoip2-golang"
	"github.com/oschwald/maxminddb-golang"
)

type ConfigStruct struct {
	MMDBASN string `toml:"mmdb_asn"`
}

var cfg ConfigStruct

type rangeinfo struct {
	nr  net.IPNet
	org string
}

var asn2ranges map[uint32][]rangeinfo

func do_asn2range(r *maxminddb.Reader) {
	asn2ranges = make(map[uint32][]rangeinfo)
	n_it := r.Networks()
	for n_it.Next() {
		var as geoip2.ASN
		nr, err := n_it.Network(&as)
		if err != nil {
			panic("n_it.Network err: " + err.Error())
		}
		nr.IP = nr.IP.To4()
		if nr.IP == nil {
			continue
		}
		asn32 := uint32(as.AutonomousSystemNumber)
		asn2ranges[asn32] = append(asn2ranges[asn32], rangeinfo{
			nr:  *nr,
			org: as.AutonomousSystemOrganization,
		})
	}
	if n_it.Err() != nil {
		panic("n_it err: " + n_it.Err().Error())
	}
}

func do_asn2range_print(gr *maxminddb.Reader) {
	fmt.Fprintf(os.Stderr, "making ASN->ranges mapping...")
	do_asn2range(gr)
	fmt.Fprintf(os.Stderr, " done.\n")
}

func getASN(r *maxminddb.Reader, ipAddress net.IP) (asn geoip2.ASN, err error) {
	err = r.Lookup(ipAddress, &asn)
	return
}

type record struct {
	Added      string            `json:"added,omitempty"`
	Whois      string            `json:"whois,omitempty"`
	WhoisDate  string            `json:"whois_date,omitempty"`
	PDB        interface{}       `json:"pdb,omitempty"`
	PDBDate    string            `json:"pdb_date,omitempty"`
	Ranges     []string          `json:"ranges,omitempty"`
	RangesOrg  map[string]string `json:"ranges_org,omitempty"`
	RangesDate string            `json:"ranges_date,omitempty"`
	Exclusions []string          `json:"exclusions,omitempty"`
}

func parseHits() {

	gr, err := maxminddb.Open(cfg.MMDBASN)
	if err != nil {
		panic("geoip2.Open: " + err.Error())
	}
	defer gr.Close()

	do_asn2range_print(gr)

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		addr := scanner.Text()
		parsed := net.ParseIP(addr)
		if parsed == nil {
			fmt.Printf("%s - failed to parse\n")
			continue
		}
		addr = parsed.String()
		asn, err := getASN(gr, parsed)
		if err != nil {
			fmt.Printf("%s - failed to lookup: %v\n", addr, err)
			continue
		}
		if asn.AutonomousSystemNumber == 0 {
			fmt.Printf("%s - failed to lookup\n", addr)
			continue
		}
		fmt.Printf("%s - OK - AS%d - %s\n",
			addr, asn.AutonomousSystemNumber, asn.AutonomousSystemOrganization)

		asn32 := uint32(asn.AutonomousSystemNumber)
		asnstr := strconv.FormatUint(uint64(asn32), 10)

		if !existsInAnyDBStr(asnstr) {
			var rec record
			fillranges(&rec, asn32)
			dumprecord(path.Join("db/dunno", asnstr), &rec)
		}
	}
}

func existsInDBStr(db, asnstr string) bool {
	if _, err := os.Stat(path.Join("db", db, asnstr)); err == nil {
		return true
	} else if os.IsNotExist(err) {
		return false
	} else {
		panic("os.Stat err: " + err.Error())
	}
}

func existsInDB(db string, asn32 uint32) bool {
	return existsInDBStr(db, strconv.FormatUint(uint64(asn32), 10))
}

func existsInAnyDBStr(asnstr string) bool {
	return existsInDBStr("dunno", asnstr) ||
		existsInDBStr("kids", asnstr) ||
		existsInDBStr("sirs", asnstr)
}

func existsInAnyDB(asn32 uint32) bool {
	return existsInAnyDBStr(strconv.FormatUint(uint64(asn32), 10))
}

func iterateDirNum(dirname string, actor func(fullpath, fname string)) error {
	f, err := os.Open(dirname)
	if err != nil {
		return err
	}
	list, err := f.Readdirnames(-1)
	f.Close()
	if err != nil {
		return err
	}
	sort.Slice(list, func(i, j int) bool {
		if len(list[i]) < len(list[j]) {
			return true
		}
		if len(list[i]) > len(list[j]) {
			return false
		}
		return list[i] < list[j]
	})
	for _, s := range list {
		actor(path.Join(dirname, s), s)
	}
	return nil
}

func iterateDirNumNoerr(dirname string, actor func(fullpath, fname string)) {
	err := iterateDirNum(dirname, actor)
	if err != nil {
		panic("iterateDirNum err: " + err.Error())
	}
}

func fillranges(rec *record, asn32 uint32) {
	rec.Ranges = nil
	rec.RangesOrg = nil
	for _, r := range asn2ranges[asn32] {
		rstr := r.nr.String()
		rec.Ranges = append(rec.Ranges, rstr)
		if rec.RangesOrg == nil {
			rec.RangesOrg = make(map[string]string)
		}
		rec.RangesOrg[rstr] = r.org
	}
}

func dumprecord(fullpath string, rec *record) {
	fcnt, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		panic("json.MarshalIndent err: " + err.Error())
	}
	err = ioutil.WriteFile(fullpath, fcnt, 0o777)
	if err != nil {
		panic("ioutil.WriteFile err: " + err.Error())
	}
}

func loadrecord(fullpath string) (rec record) {
	fcnt, err := ioutil.ReadFile(fullpath)
	if err != nil {
		panic("ioutil.ReadFile err: " + err.Error())
	}
	err = json.Unmarshal(fcnt, &rec)
	if err != nil {
		panic("json.Unmarshal err: " + err.Error())
	}
	return
}

func rerange() {
	gr, err := maxminddb.Open(cfg.MMDBASN)
	if err != nil {
		panic("geoip2.Open: " + err.Error())
	}
	defer gr.Close()

	do_asn2range_print(gr)

	rerangeone := func(fullpath, fname string) {
		if fname == "" || fname[0] == '.' {
			return
		}

		asn64, err := strconv.ParseUint(fname, 10, 32)
		if err != nil {
			panic("strconv.ParseUint err: " + err.Error())
		}
		asn32 := uint32(asn64)

		rec := loadrecord(fullpath)
		fillranges(&rec, asn32)
		dumprecord(fullpath, &rec)
	}

	fmt.Fprintf(os.Stderr, "reranging...")

	iterateDirNumNoerr("db/dunno", rerangeone)
	iterateDirNumNoerr("db/kids", rerangeone)
	iterateDirNumNoerr("db/sirs", rerangeone)

	fmt.Fprintf(os.Stderr, " done.\n")
}

func main() {

	cfgfile := flag.String("cfgfile", "config.toml", "config file")

	flag.Parse()

	cfgcont, err := ioutil.ReadFile(*cfgfile)
	if err != nil {
		panic("ioutil.ReadFile: " + err.Error())
	}

	err = toml.Unmarshal(cfgcont, &cfg)
	if err != nil {
		panic("toml.Unmarshal: " + err.Error())
	}

	if len(flag.Args()) <= 0 {
		flag.PrintDefaults()
		return
	}

	cmd := flag.Args()[0]
	switch cmd {
	case "hits":
		parseHits()
	case "rerange":
		rerange()
	default:
		fmt.Fprintf(os.Stderr, "unknown cmd: %s\n", cmd)
	}
}
