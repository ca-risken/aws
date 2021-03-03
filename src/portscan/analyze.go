package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"time"
)

func analyzeResult(target, status, service, protocol string, port int) map[string]interface{} {
	if status == "closed" {
		return nil
	}
	switch port {
	case 22:
		appLogger.Warn("ssh checker is not implemented.")
		return nil
	default:
		data, err := analyzeHTTP(target, port)
		if err != nil {
			appLogger.Warnf("failed analyze http. err:%v", err)
			return nil
		}
		return data
	}
}

func analyzeHTTP(target string, port int) (map[string]interface{}, error) {
	var url string
	if port == 443 {
		url = fmt.Sprintf("https://%v", target)
	} else if port == 80 {
		url = fmt.Sprintf("http://%v", target)
	} else {
		url = fmt.Sprintf("http://%v:%v", target, port)
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Printf("%v", err)
		return nil, err
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := http.Client{
		Timeout:   time.Duration(5 * time.Second),
		Transport: transport,
	}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("%v", err)
		return nil, err
	}
	defer resp.Body.Close()
	fmt.Printf("%v\n", map[string]interface{}{
		"status": resp.Status,
		"header": resp.Header,
	})
	ret := map[string]interface{}{
		"status": resp.Status,
		"header": resp.Header,
	}
	return ret, nil
}
