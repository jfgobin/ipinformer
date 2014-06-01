/* ***********************************************
 * virustotal.go
 *
 * Functions to access virustotal
 *
 *
 *
 * Revisions
 * ---------
 *
 * 2014 05 29 - v1.0 - Jean Gobin
 *********************************************** */

package main

import (
	"fmt"
	"net/url"
	"net/http"
	"encoding/json"
	"time"
	"os"
	"strconv"
)

/* Definition of structures */

type vtConfig struct {			// The configuration needed to access VirusTotal
	apikey string			// The API key, register on http://www.virustotal.com
	delay  int			// delay to enforce between two requests
}

type vtResult struct {
	urlKnown	bool		// Any known URLs?
	nMalwareDet	int		// Number of known malware
	nMalwareCom	int		// Number of malwares known to communicate with the IP
	nameKnown	string		// List of known names for that IP
}


func GetIPinfo(ip string, vtc vtConfig, debug bool) vtResult {
	var (
		urls 	string
		s 	url.Values
		retval	vtResult
		jT	interface {}
	)
	urls="https://www.virustotal.com/vtapi/v2/ip-address/report?"
	s=make(url.Values,0)
	s.Add("apikey",vtc.apikey)
	s.Add("ip",ip)
	if debug {
		fmt.Printf("DEBUG: GetIPinfo(): requesting %s.\n",urls+s.Encode())
	}
	resp,err := http.Get(urls+s.Encode())
	if err != nil {
		fmt.Printf("ERROR: GetIPinfo(): error while trying to open %s (%s)\n",urls,err)
		return retval 
	}
	// resp.Body contains the response, which is a json object
	jsonDecoder := json.NewDecoder(resp.Body)
	err = jsonDecoder.Decode(&jT)
	if err != nil {
		fmt.Printf("ERROR: GetIPinfo(): decoding json config (%s)\nExiting ...\n",err)
		return retval
	}
	// jT contains the various elements.
	m := jT.(map[string]interface{})
	// Let's check the response code
	// First, test for presence. 
	code,status := m["response_code"]
	if status==false || int(code.(float64)) != 1 {
		// Either the key is not in the response or the object is not known
		return retval
	}
	// If we are here, it means that the IP is known to VirusTotal
	// Next, let's find whether this IP is associated with positive URLs
	// The object is stored with the key "detected_urls", and is of type []interface{}
	// Let's just get its length
	dUrl,status := m["detected_urls"]
	if status==false {
		retval.urlKnown=false
	} else {
		if len(dUrl.([]interface{}))>0 {
			retval.urlKnown=true
		}
	}
	// Next, let's find if this IP is known to serve malware
	dDSamples,status := m["detected_downloaded_samples"]
	if status {
		// The key exists.
		retval.nMalwareDet = len(dDSamples.([]interface{}))
	}
	// Then, let's find if this IP is known to be contacted
	// by malware.
	dDComms,status := m["detected_communicating_samples"]
	if status {
		// The key exists.
		retval.nMalwareCom=len(dDComms.([]interface{}))
	}
	// And finally, if there are names, we will get them and add them to 
	// nameKnown
	dResolutions,status := m["resolutions"]
	if status {
		// The key exists. 
		// Each entry is a map composed of
		// {"last_resolved": "2014-03-10 00:00:00", "hostname": "%2A.3gpsex.com"}
		for iItem := range dResolutions.([]interface{}) {
			cItem := (dResolutions.([]interface{})[iItem]).(map[string](interface{}))
			
			if len(retval.nameKnown) == 0 {
				// First element
				retval.nameKnown=cItem["hostname"].(string)
			} else {
				retval.nameKnown=retval.nameKnown+","+cItem["hostname"].(string)
			}
		}
	}
	if debug {
		fmt.Printf("DEBUG: GetIPinfo() : enforcing %d second delay.",vtc.delay)
	}
	time.Sleep(time.Duration(vtc.delay) * time.Second)
	return retval
}

func ReadVTconfig(filename string,debug bool) (vtConfig,bool) {
	// Read the configuration file and returns the items in the configuration
	// structure
	var curCfg vtConfig
	f, err := os.Open(filename)
	if err != nil {
		if debug {
			fmt.Printf("ERROR: ReadVTconfig() - Unable to read configuration (%s), disabling VT.\n",err)
		}
		return curCfg,false
	}
	jsonDecoder := json.NewDecoder(f)
	/* We will decode the json string (in the file) into a map string -> string */
	var m map[string](string)
	err = jsonDecoder.Decode(&m)
	if err != nil {
		fmt.Printf("ERROR: ReadVTconfig() - decoding json config (%s), disabling VT\n",err)
		f.Close()
		return curCfg,false
	}
	curCfg.apikey=m["apikey"]
	curCfg.delay, err= strconv.Atoi(m["delay"])
	if (err!=nil)  {
		if debug {
			fmt.Printf("WARNING: ReadVTconfig() - cannot read delay (%s) - enforcing default of 15 seconds.\n", err)
		}
		curCfg.delay=15
	}
	f.Close()
	return curCfg,true
}
