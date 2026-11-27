// Command loadgen sends a steady stream of requests to the demo apps and
// counts failures. GET /stats returns the counts, POST /reset zeroes them.
package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

func main() {
	targets := strings.Split(env("TARGETS", "http://app1:8080/,http://app2:8080/"), ",")
	rps, _ := strconv.Atoi(env("RPS", "50"))
	var ok, failed atomic.Int64
	client := &http.Client{Timeout: 3 * time.Second}

	go func() {
		t := time.NewTicker(time.Second / time.Duration(rps))
		for i := 0; ; i++ {
			<-t.C
			target := targets[i%len(targets)]
			go func() {
				resp, err := client.Get(target)
				if err == nil {
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
				}
				if err != nil || resp.StatusCode != http.StatusOK {
					failed.Add(1)
					return
				}
				ok.Add(1)
			}()
		}
	}()
	go func() {
		for range time.Tick(5 * time.Second) {
			log.Printf("ok=%d failed=%d", ok.Load(), failed.Load())
		}
	}()

	http.HandleFunc("/stats", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]int64{"ok": ok.Load(), "failed": failed.Load()})
	})
	http.HandleFunc("/reset", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "use POST", http.StatusMethodNotAllowed)
			return
		}
		ok.Store(0)
		failed.Store(0)
	})
	log.Printf("sending %d req/s to %v", rps, targets)
	log.Fatal(http.ListenAndServe(env("ADDR", ":8090"), nil))
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
