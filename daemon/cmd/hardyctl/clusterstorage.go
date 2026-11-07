package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/cluster/san"
	"github.com/hardyos/hardyos/daemon/internal/priv"
)

// clusterStorage is `hardyctl cluster-storage`: an administrator's
// confirmations on the cluster's storage server that hardyd can't give
// (security review M1, M2; decision 377). They run as root on the
// storage server only: hardyd-priv refuses these operations to anyone
// else.
//
//	repin <node>     accept a compute server's new storage address or key
//	repin --subnet   accept a new storage network
//	forget <node>    clear everything kept of a removed server (its fence too)
func clusterStorage(socket string, args []string, in io.Reader) error {
	if len(args) < 2 {
		return errors.New("usage: hardyctl cluster-storage repin <server> | repin --subnet | forget <server>")
	}
	if os.Geteuid() != 0 {
		return errors.New("cluster-storage must run as root on the storage server")
	}
	verb, target := args[0], args[1]
	var op string
	var req any
	switch {
	case verb == "repin" && target == "--subnet":
		if err := confirmTyped(in, "the storage network", "subnet"); err != nil {
			return err
		}
		op, req = san.OpPinReset, san.PinResetArgs{Subnet: true, Confirm: "subnet"}
	case verb == "repin":
		if err := san.ValidNode(cluster.NodeID(target)); err != nil {
			return err
		}
		if err := confirmTyped(in, target+"'s storage address and key", target); err != nil {
			return err
		}
		op, req = san.OpPinReset, san.PinResetArgs{Node: cluster.NodeID(target), Confirm: target}
	case verb == "forget":
		if err := san.ValidNode(cluster.NodeID(target)); err != nil {
			return err
		}
		if err := confirmTyped(in, "everything the storage server keeps of "+target+" (its fence included)", target); err != nil {
			return err
		}
		op, req = san.OpForget, san.ForgetArgs{Node: cluster.NodeID(target), Confirm: target}
	default:
		return fmt.Errorf("unknown cluster-storage command %q", verb)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := priv.NewClient(socket).Call(ctx, op, req, nil); err != nil {
		return err
	}
	fmt.Println("done; the storage agent applies the cluster's current state on its next pass")
	return nil
}

// confirmTyped asks for the name to be typed again.
func confirmTyped(in io.Reader, what, name string) error {
	fmt.Printf("This resets %s. Type %q to confirm: ", what, name)
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && line == "" {
		return errors.New("not confirmed")
	}
	if strings.TrimSpace(line) != name {
		return errors.New("not confirmed")
	}
	return nil
}
