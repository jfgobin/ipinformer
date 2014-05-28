/* ***********************************************
 * config.go
 *
 * Functions to read the configuration file
 *
 * The config files will be JSON encoded maps like
 * {
 *   'sname': [ type,target,name],
 *   ...
 * }
 *
 * Where:
 * sname is the short name (i.e. the one that 
 *       appears in the CSV file)
 * type is 'URL' or 'FILE'
 * target is the path/filename or URL, depending
 *       on the type
 * name is the long name, used to display how
 *       many IPs are in the list. 
 *
 * Revisions
 * ---------
 *
 * 2014 05 26 - v1.0 - Jean Gobin
 *********************************************** */

package main

import (
	"fmt"
	"os"
	"encoding/json"
)


func Readconfig(filename string, debug bool) []mallistentry {
	var (
		malwarelist []mallistentry
		entry mallistentry
		item []string
	)
	f, err := os.Open(filename)
	if err != nil {
		/* Something went wrong */
		fmt.Printf("ERROR: while opening %s (%s)\nExiting ...\n",filename,err)
		os.Exit(-3)
	}
	/* We now have a *File, let's pass that to the json reader/decoder */
	jsonDecoder := json.NewDecoder(f)
	/* We will decode the json string (in the file) into a map string -> []string */
	var m map[string]([]string)
	err = jsonDecoder.Decode(&m)
	if err != nil {
		fmt.Printf("ERROR: decoding json config (%s)\nExiting ...\n",err)
		f.Close()
	}
	for k := range m {
		item=m[k]
		entry.method=item[0]
		entry.target=item[1]
		entry.name=item[2]
		entry.sname=k
		entry.iplist=nil
		malwarelist = append(malwarelist,entry)
	}	
	return malwarelist
}

