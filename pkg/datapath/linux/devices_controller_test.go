// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package linux

import (
	"context"
	"errors"
	"log/slog"
	"maps"
	"net"
	"os"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/script"
	"github.com/cilium/hive/script/scripttest"
	"github.com/cilium/statedb"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
)

func TestPrivilegedDevicesControllerScript(t *testing.T) {
	testutils.PrivilegedTest(t)

	setup := func(t testing.TB, args []string) *script.Engine {
		var err error

		// Run the test in a new network namespace.
		origNS := netns.None()
		newNS := netns.None()
		runtime.LockOSThread()
		t.Cleanup(func() {
			if origNS.IsOpen() {
				netns.Set(origNS)
				origNS.Close()
			}
			if newNS.IsOpen() {
				newNS.Close()
			}
			runtime.UnlockOSThread()
		})
		origNS, err = netns.Get()
		assert.NoError(t, err)
		newNS, err = netns.New()
		assert.NoError(t, err)

		h := hive.New(
			DevicesControllerCell,
			cell.Provide(func(log *slog.Logger) (*netlinkFuncs, error) {
				// Provide the normal netlink interface, restricted to the test network namespace.
				return makeNetlinkFuncs(log, defaults.NeighborNetlinkBufferSize)
			}),
		)

		log := hivetest.Logger(t)
		t.Cleanup(func() {
			assert.NoError(t, h.Stop(log, context.TODO()))
		})

		// Parse the shebang arguments in the script.
		flags := pflag.NewFlagSet("", pflag.ContinueOnError)
		h.RegisterFlags(flags)
		require.NoError(t, flags.Parse(args), "flags.Parse")

		cmds, err := h.ScriptCommands(log)
		require.NoError(t, err, "ScriptCommands")
		maps.Insert(cmds, maps.All(script.DefaultCmds()))

		return &script.Engine{
			Cmds: cmds,
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	scripttest.Test(t,
		ctx,
		setup,
		[]string{"PATH=" + os.Getenv("PATH")},
		"testdata/device-*.txtar")
}

func TestNeighSubscribeOptions(t *testing.T) {
	errorCallback := func(error) {}
	ns := netns.None()

	t.Run("configured size is applied and forced", func(t *testing.T) {
		opts := neighSubscribeOptions(defaults.NeighborNetlinkBufferSize, &ns, errorCallback)
		assert.Equal(t, defaults.NeighborNetlinkBufferSize, opts.ReceiveBufferSize)
		assert.True(t, opts.ReceiveBufferForceSize, "buffer size should be forced past net.core.rmem_max")
		assert.Same(t, &ns, opts.Namespace)
		assert.False(t, opts.ListExisting)
	})

	t.Run("zero size leaves kernel default in place", func(t *testing.T) {
		opts := neighSubscribeOptions(0, &ns, errorCallback)
		assert.Equal(t, 0, opts.ReceiveBufferSize)
		assert.False(t, opts.ReceiveBufferForceSize)
	})

	t.Run("negative size is normalized to kernel default", func(t *testing.T) {
		opts := neighSubscribeOptions(-1, &ns, errorCallback)
		assert.Equal(t, 0, opts.ReceiveBufferSize)
		assert.False(t, opts.ReceiveBufferForceSize)
	})
}

func TestSubscribeNeighWithBufferFallback(t *testing.T) {
	log := hivetest.Logger(t)
	ns := netns.None()
	cb := func(error) {}

	type call struct {
		size  int
		force bool
	}

	newFake := func(errs ...error) (*[]call, func(netlink.NeighSubscribeOptions) error) {
		calls := &[]call{}
		i := 0
		return calls, func(opts netlink.NeighSubscribeOptions) error {
			*calls = append(*calls, call{opts.ReceiveBufferSize, opts.ReceiveBufferForceSize})
			var err error
			if i < len(errs) {
				err = errs[i]
			}
			i++
			return err
		}
	}

	t.Run("success on forced attempt does not latch", func(t *testing.T) {
		var flag atomic.Bool
		calls, sub := newFake(nil)
		require.NoError(t, subscribeNeighWithBufferFallback(sub, 4096, &ns, cb, &flag, log))
		require.Len(t, *calls, 1)
		assert.Equal(t, call{4096, true}, (*calls)[0])
		assert.False(t, flag.Load())
	})

	t.Run("EPERM falls back to kernel default and latches", func(t *testing.T) {
		var flag atomic.Bool
		calls, sub := newFake(unix.EPERM, nil)
		require.NoError(t, subscribeNeighWithBufferFallback(sub, 4096, &ns, cb, &flag, log))
		require.Len(t, *calls, 2)
		assert.Equal(t, call{4096, true}, (*calls)[0])
		assert.Equal(t, call{0, false}, (*calls)[1], "fallback must not force the buffer")
		assert.True(t, flag.Load(), "EPERM should latch so future restarts skip forcing")
	})

	t.Run("latched flag skips forcing without falling back", func(t *testing.T) {
		var flag atomic.Bool
		flag.Store(true)
		calls, sub := newFake(nil)
		require.NoError(t, subscribeNeighWithBufferFallback(sub, 4096, &ns, cb, &flag, log))
		require.Len(t, *calls, 1)
		assert.Equal(t, call{0, false}, (*calls)[0])
	})

	t.Run("non-EPERM error propagates without fallback or latch", func(t *testing.T) {
		var flag atomic.Bool
		wantErr := errors.New("socket setup failed")
		calls, sub := newFake(wantErr)
		err := subscribeNeighWithBufferFallback(sub, 4096, &ns, cb, &flag, log)
		require.ErrorIs(t, err, wantErr)
		require.Len(t, *calls, 1, "must not fall back on a non-EPERM error")
		assert.False(t, flag.Load(), "must not latch on a transient/unrelated error")
	})

	t.Run("fallback error propagates and still latches", func(t *testing.T) {
		var flag atomic.Bool
		fallbackErr := errors.New("still broken")
		calls, sub := newFake(unix.EPERM, fallbackErr)
		err := subscribeNeighWithBufferFallback(sub, 4096, &ns, cb, &flag, log)
		require.ErrorIs(t, err, fallbackErr)
		require.Len(t, *calls, 2)
		assert.True(t, flag.Load())
	})

	t.Run("latch persists across restarts: force once, then never again", func(t *testing.T) {
		var flag atomic.Bool
		calls, sub := newFake(unix.EPERM, nil, nil)

		require.NoError(t, subscribeNeighWithBufferFallback(sub, 4096, &ns, cb, &flag, log))
		require.NoError(t, subscribeNeighWithBufferFallback(sub, 4096, &ns, cb, &flag, log))

		require.Len(t, *calls, 3, "first call forces+falls back (2), second skips forcing (1)")
		assert.Equal(t, call{4096, true}, (*calls)[0])
		assert.Equal(t, call{0, false}, (*calls)[1])
		assert.Equal(t, call{0, false}, (*calls)[2], "second restart must not re-attempt forcing")
	})

	t.Run("disabled buffer returns the error without forcing or latching", func(t *testing.T) {
		var flag atomic.Bool
		wantErr := unix.EPERM // even EPERM must not latch when forcing wasn't requested
		calls, sub := newFake(wantErr)
		err := subscribeNeighWithBufferFallback(sub, 0, &ns, cb, &flag, log)
		require.ErrorIs(t, err, wantErr)
		require.Len(t, *calls, 1)
		assert.Equal(t, call{0, false}, (*calls)[0])
		assert.False(t, flag.Load())
	})
}

func TestNeighborNetlinkBufferSize_Config(t *testing.T) {
	newConfig := func(t *testing.T, args ...string) DevicesConfig {
		var got DevicesConfig
		h := hive.New(
			cell.Config(DevicesConfig{}),
			cell.Invoke(func(cfg DevicesConfig) { got = cfg }),
		)
		flags := pflag.NewFlagSet("", pflag.ContinueOnError)
		h.RegisterFlags(flags)
		require.NoError(t, flags.Parse(args))
		require.NoError(t, h.Populate(hivetest.Logger(t)))
		return got
	}

	t.Run("default is applied", func(t *testing.T) {
		cfg := newConfig(t)
		assert.Equal(t, defaults.NeighborNetlinkBufferSize, cfg.NeighborNetlinkBufferSize)
	})

	t.Run("flag overrides default", func(t *testing.T) {
		cfg := newConfig(t, "--"+option.NeighborNetlinkBufferSize+"=1024")
		assert.Equal(t, 1024, cfg.NeighborNetlinkBufferSize)
	})
}

func TestDevicesController_Restarts(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var (
		db           *statedb.DB
		devicesTable statedb.Table[*tables.Device]
	)

	// Is this the first subscription?
	var first atomic.Bool
	first.Store(true)

	funcs := netlinkFuncs{
		AddrList: func(link netlink.Link, family int) ([]netlink.Addr, error) {
			return nil, nil
		},

		Close: func() error {
			return nil
		},

		LinkList: func() ([]netlink.Link, error) {
			if first.Load() {
				// On first round we create a stale device that should get flushed
				// from the devices table.
				return []netlink.Link{&netlink.Dummy{
					LinkAttrs: netlink.LinkAttrs{
						Index:        2,
						Name:         "stale",
						HardwareAddr: []byte{2, 3, 4, 5, 6, 7},
					},
				}}, nil
			}
			return nil, nil
		},

		NeighList: func(linkIndex, family int) ([]netlink.Neigh, error) { return nil, nil },

		RouteListFiltered: func(family int, filter *netlink.Route, filterMask uint64) ([]netlink.Route, error) {
			return nil, nil
		},

		RouteSubscribe: func(ch chan<- netlink.RouteUpdate, done <-chan struct{}, errorCallback func(error)) error {
			go func() {
				defer close(ch)
				if !first.Load() {
					_, ipn, _ := net.ParseCIDR("1.2.3.0/24")
					select {
					case <-done:
					case ch <- netlink.RouteUpdate{
						Type: unix.RTM_NEWROUTE,
						Route: netlink.Route{
							LinkIndex: 1,
							Table:     unix.RT_TABLE_DEFAULT,
							Scope:     unix.RT_SCOPE_SITE,
							Dst:       ipn,
						},
					}:
					}
				}
				<-done
			}()
			return nil
		},
		AddrSubscribe: func(ch chan<- netlink.AddrUpdate, done <-chan struct{}, errorCallback func(error)) error {
			go func() {
				defer close(ch)
				if !first.Load() {
					_, ipn, _ := net.ParseCIDR("1.2.3.4/24")
					select {
					case <-done:
					case ch <- netlink.AddrUpdate{
						LinkAddress: *ipn,
						LinkIndex:   1,
						NewAddr:     true,
					}:
					}
				}
				<-done
			}()
			return nil
		},
		LinkSubscribe: func(ch chan<- netlink.LinkUpdate, done <-chan struct{}, errorCallback func(error)) error {
			go func() {
				defer close(ch)
				if first.Load() {
					// Simulate a netlink socket failure on the first subscription round
					errorCallback(errors.New("first"))
					first.Store(false)
				} else {
					select {
					case <-done:
					case ch <- netlink.LinkUpdate{
						IfInfomsg: nl.IfInfomsg{IfInfomsg: unix.IfInfomsg{Index: 1}},
						Header:    unix.NlMsghdr{Type: unix.RTM_NEWLINK},
						Link: &netlink.Dummy{
							LinkAttrs: netlink.LinkAttrs{
								Index:        1,
								Name:         "dummy",
								HardwareAddr: []byte{1, 2, 3, 4, 5, 6},
							},
						},
					}:
					}
				}
				<-done
			}()
			return nil
		},
		NeighSubscribe: func(ch chan<- netlink.NeighUpdate, done <-chan struct{}, errorCallback func(error)) error {
			go func() {
				defer close(ch)
				if !first.Load() {
					select {
					case <-done:
					case ch <- netlink.NeighUpdate{
						Type: unix.RTM_NEWNEIGH,
						Neigh: netlink.Neigh{
							LinkIndex:    1,
							IP:           net.ParseIP("1.2.3.4"),
							HardwareAddr: []byte{1, 2, 3, 4, 5, 6},
						},
					}:
					}
				}
				<-done
			}()
			return nil
		},
	}

	tlog := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))
	h := hive.New(
		DevicesControllerCell,
		cell.Provide(func() *netlinkFuncs { return &funcs }),
		cell.Invoke(func(db_ *statedb.DB, devicesTable_ statedb.Table[*tables.Device]) {
			db = db_
			devicesTable = devicesTable_
		}))

	err := h.Start(tlog, ctx)
	assert.NoError(t, err)

	for {
		rxn := db.ReadTxn()
		iter, invalidated := devicesTable.AllWatch(rxn)
		devs := statedb.Collect(iter)

		// We expect the 'stale' device to have been flushed by the restart
		// and for the 'dummy' to have appeared.
		if len(devs) == 1 && devs[0].Name == "dummy" {
			break
		}

		select {
		case <-ctx.Done():
			rxn.WriteJSON(os.Stdout)
			t.Fatalf("Test timed out while waiting for device, last seen: %v", devs)
		case <-invalidated:
		}
	}

	err = h.Stop(tlog, ctx)
	assert.NoError(t, err)

}
