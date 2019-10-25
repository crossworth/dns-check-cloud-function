package dnscheck

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type JsonError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type CheckServer struct {
	Name string
	IP   string
}

type DNSResponse struct {
	Server   string `json:"server"`
	Response string `json:"response"`
}

type Response struct {
	Domain    string        `json:"domain"`
	Responses []DNSResponse `json:"responses"`
}

func DNSCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	domain := r.URL.Query().Get("domain")
	if domain == "" {
		writeJsonError(w, &JsonError{
			Code:    400,
			Message: "you must provide the domain",
		})
		return
	}

	file, err := os.Open("./list.csv")
	if err != nil {
		writeJsonError(w, &JsonError{
			Code:    500,
			Message: err.Error(),
		})
		return
	}

	list, err := readDNSList(file)
	if err != nil {
		writeJsonError(w, &JsonError{
			Code:    500,
			Message: err.Error(),
		})
		return
	}

	var lock sync.Mutex
	var wg sync.WaitGroup
	var responses []DNSResponse
	wg.Add(len(list))

	for _, s := range list {
		go func(s CheckServer) {
			defer wg.Done()
			resp := resolveDomain(domain, s.IP)
			lock.Lock()
			defer lock.Unlock()
			responses = append(responses, DNSResponse{
				Server:   s.Name,
				Response: resp,
			})
		}(s)
	}

	wg.Wait()
	w.WriteHeader(200)
	_ = json.NewEncoder(w).Encode(&Response{
		Domain:    domain,
		Responses: responses,
	})
}

func writeJsonError(w http.ResponseWriter, jsonError *JsonError) {
	w.WriteHeader(jsonError.Code)
	_ = json.NewEncoder(w).Encode(jsonError)
}

func resolveDomain(domain string, server string) string {
	client := dns.Client{
		Timeout: 1 * time.Second,
	}

	msg := dns.Msg{}
	msg.SetQuestion(domain+".", dns.TypeA)

	r, _, err := client.Exchange(&msg, server+":53")
	if err != nil {
		return err.Error()
	}

	if len(r.Answer) == 0 {
		return "no results"
	}

	var result []string
	for _, ans := range r.Answer {
		if rec, ok := ans.(*dns.A); ok {
			result = append(result, rec.A.String())
		}
	}

	return strings.Join(result, ", ")
}

func readDNSList(input io.Reader) ([]CheckServer, error) {
	var list []CheckServer

	r := csv.NewReader(input)

	for {
		record, err := r.Read()
		if err == io.EOF {
			break
		}

		if err != nil || len(record) < 2 {
			return list, fmt.Errorf("could not parse dns list")
		}

		list = append(list, CheckServer{
			Name: strings.TrimSpace(record[0]),
			IP:   strings.TrimSpace(record[1]),
		})
	}

	return list, nil
}
