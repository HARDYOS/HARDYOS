//go:build cgo

// Command hardyos-nss looks a user up through the system's name service
// (NSS: /etc/passwd, then winbind for domain accounts) and prints their user
// ID, primary group and every group they're in, as JSON:
//
//	hardyos-nss user 'HOME\alice'   ->  {"uid":101105,"gid":100513,"groups":[100513,101107]}
//
// hardyd-priv uses it to know which Linux identity to read and write files
// as (docs/plans/file-sharing.md section 3). It exists because hardyd-priv
// is built without cgo, and Go's user lookup then reads only the local
// files, never winbind. This binary is built with cgo, so os/user calls the
// C library's getpwnam_r and getgrouplist. It only looks things up.
//
// Exit codes: 0 found, 2 no such user, 1 anything else.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"unicode/utf8"
)

type result struct {
	UID    int   `json:"uid"`
	GID    int   `json:"gid"`
	Groups []int `json:"groups"`
}

func main() {
	if len(os.Args) != 3 || os.Args[1] != "user" || os.Args[2] == "" || len(os.Args[2]) > 200 || !utf8.ValidString(os.Args[2]) {
		fmt.Fprintln(os.Stderr, "usage: hardyos-nss user NAME")
		os.Exit(1)
	}
	u, err := user.Lookup(os.Args[2])
	var unknown user.UnknownUserError
	if errors.As(err, &unknown) {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	res := result{Groups: []int{}}
	if res.UID, err = strconv.Atoi(u.Uid); err != nil {
		fail(err)
	}
	if res.GID, err = strconv.Atoi(u.Gid); err != nil {
		fail(err)
	}
	gids, err := u.GroupIds()
	if err != nil {
		fail(err)
	}
	for _, g := range gids {
		n, err := strconv.Atoi(g)
		if err != nil {
			fail(err)
		}
		res.Groups = append(res.Groups, n)
	}
	if err := json.NewEncoder(os.Stdout).Encode(res); err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
