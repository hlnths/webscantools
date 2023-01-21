package main

import (
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/hlnths/hamravesh/nuclei"
	"github.com/hlnths/hamravesh/subfinder"
	"github.com/hlnths/hamravesh/types"
)

var scans = make([]types.Scan, 0, 100)

func main() {
	router := gin.Default()
	router.GET("/api/scan", getScans)
	router.POST("/api/scan", postScan)
	router.GET("/api/result/:id", getResult)
	runWorker()
	router.Run()
}

func runWorker() {
	ticker := time.NewTicker(time.Second)
	requestLimit, err := strconv.Atoi(os.Getenv("REQUEST_LIMIT"))
	if err != nil || requestLimit < 1 {
		requestLimit = 1
	}

	go func() {
		for {
			select {
			case <-ticker.C:
				if len(scans) != 0 {
					var scan *types.Scan
					processingReqCount := 0

					for i, check := range scans {
						if check.Status == types.Ongoing {
							processingReqCount++
							if processingReqCount >= requestLimit {
								break
							}
						} else if check.Status == types.Queued {
							scan = &scans[i]
							break
						}
					}

					if scan != nil {
						scan.Status = types.Ongoing
						scan.SubDomains = subfinder.GetSubDomains(scan.Domain)
						vc := make(chan map[string]types.Vulnerability)
						nuclei.ScanVulnerabilities(&(scan.SubDomains), &vc)
						for v := range vc {
							for k, v := range v {
								r, ok := scan.Vulnerabilities[k]
								if ok {
									r.Report = append(r.Report, v.Report...)
									scan.Vulnerabilities[k] = r
								} else {
									r = types.Vulnerability{}
									r.Report = v.Report
									r.IP = v.IP
									scan.Vulnerabilities[k] = r
								}
							}
						}
						scan.Status = types.Finished
					}
				}
			}
		}
	}()

}

func getScans(c *gin.Context) {
	c.IndentedJSON(http.StatusOK, scans)
}

func getResult(c *gin.Context) {
	id := c.Param("id")

	for _, s := range scans {
		if s.ID == id {
			result := map[string]interface{}{"date": s.Date}
			if len(s.Vulnerabilities) == 0 {
				result["subdomains"] = s.SubDomains
			} else {
				result["subdomains"] = s.Vulnerabilities
			}
			c.IndentedJSON(http.StatusFound, result)
			return
		}
	}
	c.IndentedJSON(http.StatusNotFound, gin.H{"message": "scan not found"})
}

func postScan(c *gin.Context) {
	var newScan types.Scan

	if err := c.BindJSON(&newScan); err != nil {
		return
	}

	newScan.ID = uuid.NewString()
	newScan.Date = time.Now().Format("2006-01-02 3:4:5 pm")
	newScan.Status = types.Queued
	newScan.SubDomains = make([]string, 0)
	newScan.Vulnerabilities = make(map[string]types.Vulnerability)
	scans = append(scans, newScan)

	c.IndentedJSON(http.StatusCreated, map[string]interface{}{"scan_id": newScan.ID})
}
