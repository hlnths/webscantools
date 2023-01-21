package subfinder

import (
	"bytes"

	"github.com/hlnths/subfinder/v2/pkg/resolve"
	"github.com/hlnths/subfinder/v2/pkg/runner"
)

func GetSubDomains(domain string) (subDomains []string) {
	buf := bytes.Buffer{}
	runnerInstance, err := runner.NewRunner(&runner.Options{
		Domain:             []string{domain},
		Output:             &buf,
		Threads:            10,                       // Thread controls the number of threads to use for active enumerations
		Timeout:            30,                       // Timeout is the seconds to wait for sources to respond
		MaxEnumerationTime: 10,                       // MaxEnumerationTime is the maximum amount of time in mins to wait for enumeration
		Resolvers:          resolve.DefaultResolvers, // Use the default list of resolvers by marshaling it to the config
		ResultCallback: func(s *resolve.HostEntry) { // Callback function to execute for available host
			subDomains = append(subDomains, s.Host)
		},
	})

	if err == nil {
		runnerInstance.RunEnumeration()
	}

	return subDomains

}
