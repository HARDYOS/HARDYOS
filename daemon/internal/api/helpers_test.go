package api

import (
	"net/url"
	"strconv"
)

func itoa(n int) string { return strconv.Itoa(n) }

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}
