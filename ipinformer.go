/* ***********************************************
 * ipinformer
 *
 * Process a list of IPs provided in a file
 * against various malware lists and returns
 * a CSV file with the suspicious entries,
 * defined by any IP seen in one or more list.
 *
 * Revision
 * --------
 *
 * 2014 05 24 - v1.0 - Jean Gobin
 * 2014 05 26 - v1.1 - Jean Gobin
 *
 *********************************************** */

package main

/* Imports */

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"encoding/csv"
	"net"
	"github.com/oschwald/geoip2-golang"
)

/* Global variables */

var Version_major int = 1
var Version_minor int = 0

type mallistentry struct {
	method string    /* The method used to access the list */
	target string    /* The list location */
	name   string    /* The name of the list */
	sname  string    /* The short name of the list (for the CSV file) */
	iplist *[]string /* The IPs in the list */
}

func main() {
	var (
		vflag              = flag.Bool("v", false, "Shows the code and packages versions")
		dflag              = flag.Bool("D", false, "Enable debug mode, prints additional information")
		outflag            = flag.String("o", "ipinformer.csv", "Name the output file")
		inflag             = flag.String("i", "ip.txt", "Name of the input file")
		geoflag		   = flag.String("g", "GeoLite2-country.mmdb", "Path and filename of the GeoLocation DB")
		iplist,csvlist     []string
		i, j               int
		ce                 *mallistentry
		line, ip           string
		isPrefix           bool
		errread            error
		lineread, linebyte []byte
		ipcount, ipmal     int
		mlpos              int
	)
	malwarelists := []mallistentry{
		{
			method: "URL",
			target: "https://zeustracker.abuse.ch/blocklist.php?download=badips",
			name:   "Abuse.ch Zeus Tracker",
			sname:  "zeustracker",
			iplist: nil},
		{
			method: "URL",
			target: "https://spyeyetracker.abuse.ch/blocklist.php?download=ipblocklist",
			name:   "Abuse.ch SpyEye Tracker",
			sname:  "spyeyetracker",
			iplist: nil},
		{
			method: "URL",
			target: "https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist",
			name:   "Abuse.ch Palevo Tracker",
			sname:  "palevotracker",
			iplist: nil},
		{
			method: "URL",
			target: "https://feodotracker.abuse.ch/blocklist/?download=ipblocklist",
			name:   "Abuse.ch Feodo Tracker",
			sname:  "feodotracker",
			iplist: nil},
		{
			method: "URL",
			target: "http://www.malwaredomainlist.com/hostslist/ip.txt",
			name:   "Malware Domain List",
			sname:  "mdl",
			iplist: nil}}
	flag.Parse()
	if *vflag {
		fmt.Printf("ipinformer version %d.%d\n\n", Version_major, Version_minor)
		fmt.Printf("Packages:\n")
	}
	fmt.Printf("Infile: %s, Outfile: %s\n", *inflag, *outflag)
	/* Load the lists in memory */
	for i = 0; i < len(malwarelists); i++ {
		ce = &malwarelists[i]
		iplist = Getmalwarelist(ce.method, ce.target, *dflag)
		fmt.Printf("List: %s: ", ce.name)
		if iplist != nil {
			fmt.Printf("%d elements\n", len(iplist))
			ce.iplist = new([]string)
			*ce.iplist = make([]string, len(iplist))
			for j = 0; j < len(iplist); j++ {
				(*ce.iplist)[j] = iplist[j]
			}
		} else {
			fmt.Printf("returned nil\n")
		}
	}
	/* Open the input file and process it line by line */
	/* Do not load it in memory in the event it is very large */
	f, err := os.Open(*inflag)
	if err != nil {
		fmt.Printf("ERROR: unable to open %s (%s)\nExiting ...\n", *inflag, err)
		os.Exit(-1)
	}
	r := bufio.NewReader(f)
	/* Opens the GeoDB and set geoPresent as needed
	   d is the delta between the index and the real position in the
	   csv file. 1 if there is only the IP, 2 if there is the IP and 
	   the country */
	geoPresent := true
	d:=2
	geoDB,err := geoip2.Open(*geoflag)
	if err != nil {
		geoPresent=false
		d=1
	}
	/* Open the output file and write the list of headers */
	fout, err := os.Create(*outflag)
	if err != nil {
		fmt.Printf("ERROR: unable to create %s (%s)\nExiting ...\n",*outflag,err)
		os.Exit(-1)
	}
	wcsv := csv.NewWriter(fout)
	csvlist = append(csvlist,"IP")
	if geoPresent {
		csvlist = append(csvlist,"Country")
	}
	for i=0; i<len(malwarelists); i++ {
		csvlist = append(csvlist, malwarelists[i].sname)
	}
	wcsv.Write(csvlist)
	wcsv.Flush()
	errread = nil
	for errread == nil {
		isPrefix = true
		for errread == nil && isPrefix {
			lineread, isPrefix, errread = r.ReadLine()
			linebyte = append(linebyte, lineread...)
		}
		line = string(linebyte)
		if *dflag {
			fmt.Printf("DEBUG: Readentries(): read %s\n", line)
		}
		ip = GetIPaddress(line)
		if ip != "" {
			ipcount++
			mlpos = 0
			mlposflag := make([]bool,len(malwarelists))
			csvlist[0]=ip
			if geoPresent {
				record,err := geoDB.Country(net.ParseIP(ip))
				if err != nil {
					csvlist[1] = "???"
				} else {
					csvlist[1] = record.Country.Names["en"]
				}
			}
			for i = 0; i < len(malwarelists); i++ {
				mlposflag[i]=false
				csvlist[i+d]="N"
				if malwarelists[i].iplist != nil {
					if Checkinlist(ip, *malwarelists[i].iplist) {
						mlpos++
						mlposflag[i]=true
						csvlist[i+d]="Y"
					}
				}
			}
			if mlpos > 0 {
				if *dflag {
					fmt.Printf("DEBUG: %s is present in at least one list.\n", ip)
				}
				ipmal++
				wcsv.Write(csvlist)
			}
		}
		linebyte = nil
	}
	fmt.Printf("Processed %d IPs, %d IPs in malware lists.\n", ipcount, ipmal)
	wcsv.Flush()
	fout.Close()
	if geoPresent {
		geoDB.Close()
	}
	f.Close()

}

/* Check if IP is in iplist. Returns true if so
   Todo : replace this linear search with a faster
   search, such as dichotomic. Requires sorted list. */
func Checkinlist(ip string, iplist []string) bool {
	var (
		i int
	)
	for i = 0; i < len(iplist); i++ {
		if iplist[i] == ip {
			return true
		}
	}
	return false
}
