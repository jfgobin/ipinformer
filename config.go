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
	'fmt'
	'os'
	'sys'
	'encoding/json'
)

/* Defined in ipinformer.go
type mallistentry struct {
        method string    /* The method used to access the list */
        target string    /* The list location */
        name   string    /* The name of the list */
        sname  string    /* The short name of the list (for the CSV file) */
        iplist *[]string /* The IPs in the list */
*/

func Readconfig(filename string, debug bool) []mallistentry {
	malwarelist []mallistentry
	f, err = os.Open(filename)
	if err != nil {
		/* Something went wrong */
		fmt.Printf("ERROR: while opening %s (%s)\nExiting ...\n",filename,err)
		sys.Exit(-3)
	}
	/* We now have a *File, let's pass that to the json reader/decoder */
	jsonDecoder = json.NewDecoder(f)
	
	
}

