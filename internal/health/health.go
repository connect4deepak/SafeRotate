// Package health reads the error rate of the affected services from Prometheus.
package health

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// Prometheus evaluates Query (which must return one number, the error ratio).
type Prometheus struct {
	URL   string
	Query string
}

var client = &http.Client{Timeout: 5 * time.Second}

// ErrorRate returns the current error ratio. No traffic (NaN or no data) is 0.
func (p Prometheus) ErrorRate(ctx context.Context) (float64, error) {
	u := p.URL + "/api/v1/query?query=" + url.QueryEscape(p.Query)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	var body struct {
		Status string `json:"status"`
		Error  string `json:"error"`
		Data   struct {
			Result []struct {
				Value [2]any `json:"value"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return 0, err
	}
	if body.Status != "success" {
		return 0, fmt.Errorf("prometheus: %s", body.Error)
	}
	if len(body.Data.Result) == 0 {
		return 0, nil
	}
	s, _ := body.Data.Result[0].Value[1].(string)
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, err
	}
	if math.IsNaN(v) {
		return 0, nil
	}
	return v, nil
}
