# Plan: Implement `ReleaseIPs` for Azure IPAM

## Context

`ReleaseIPs` at `pkg/azure/ipam/node.go:73-75` returns `fmt.Errorf("not implemented")`, meaning excess IPs are never released on Azure nodes. Two compounding problems:

1. `PrepareIPRelease` (line 61) returns an empty `ReleaseAction` — nothing is selected for release.
2. `AllocatorAzure.Start` in `pkg/ipam/allocator/azure/azure.go:76` hardcodes `releaseExcessIPs=false` in `NewNodeManager` — the node manager never invokes the release path at all, regardless of node-level code.

Both layers must be fixed. Compare with AWS (`AWSReleaseExcessIPs` flag) and Alibaba (`AlibabaCloudReleaseExcessIPs` flag), which both wire the operator option through to `NewNodeManager`.

## Files to Modify (8 files)

| File | Change |
|---|---|
| `operator/option/config.go` | Add `AzureReleaseExcessIPs` option constant |
| `operator/pkg/ipam/azure.go` | Add `AzureReleaseExcessIPs bool` to `AzureConfig`; add CLI flag; pass to `AllocatorAzure` |
| `pkg/ipam/allocator/azure/azure.go` | Add `AzureReleaseExcessIPs bool` to `AllocatorAzure`; pass to `NewNodeManager` |
| `pkg/azure/ipam/instances.go` | Add two methods to `AzureAPI` interface |
| `pkg/azure/api/api.go` | Implement `UnassignPrivateIpAddressesVM` + VMSS variant |
| `pkg/azure/api/mock/mock.go` | Implement mock versions + extend `Operation` enum |
| `pkg/azure/ipam/node.go` | Fix `PrepareIPRelease`; implement `ReleaseIPs` |
| `pkg/azure/ipam/node_test.go` | Tests for both functions |

---

## Step 1 — Operator option constant (`operator/option/config.go`)

Add alongside `AWSReleaseExcessIPs` and `AlibabaCloudReleaseExcessIPs`:
```go
AzureReleaseExcessIPs = "azure-release-excess-ips"
```

---

## Step 2 — Operator Azure config + flag (`operator/pkg/ipam/azure.go`)

```go
type AzureConfig struct {
    // ... existing fields ...
    AzureReleaseExcessIPs bool
}

var azureDefaultConfig = AzureConfig{
    // ... existing fields ...
    AzureReleaseExcessIPs: false,
}

func (cfg AzureConfig) Flags(flags *pflag.FlagSet) {
    // ... existing flags ...
    flags.Bool(operatorOption.AzureReleaseExcessIPs, azureDefaultConfig.AzureReleaseExcessIPs, "Enable releasing excess free IP addresses from Azure NICs.")
}
```

Pass `p.AzureCfg.AzureReleaseExcessIPs` into `AllocatorAzure`:
```go
allocator := &azure.AllocatorAzure{
    // ... existing fields ...
    AzureReleaseExcessIPs: p.AzureCfg.AzureReleaseExcessIPs,
}
```

---

## Step 3 — AllocatorAzure wiring (`pkg/ipam/allocator/azure/azure.go`)

```go
type AllocatorAzure struct {
    // ... existing fields ...
    AzureReleaseExcessIPs bool
}
```

Change `NewNodeManager` call (line 76) from:
```go
nodeManager, err := ipam.NewNodeManager(..., false, 0, false)
```
to:
```go
nodeManager, err := ipam.NewNodeManager(..., a.AzureReleaseExcessIPs, 0, false)
```

---

## Step 4 — Extend `AzureAPI` interface (`pkg/azure/ipam/instances.go:24`)

Add to the interface:
```go
UnassignPrivateIpAddressesVM(ctx context.Context, interfaceName string, ips []string) error
UnassignPrivateIpAddressesVMSS(ctx context.Context, instanceID, vmssName, interfaceName string, ips []string) error
```

---

## Step 5 — Implement in `pkg/azure/api/api.go`

**`UnassignPrivateIpAddressesVM`** (mirrors `AssignPrivateIpAddressesVM`):
1. `c.interfaces.Get(ctx, c.resourceGroup, interfaceName, nil)` — rate-limited + metrics
2. Build set from `ips`; filter `iface.Properties.IPConfigurations` — drop configs where `PrivateIPAddress` is in the set; guard against removing primary (`Primary == true`)
3. `c.interfaces.BeginCreateOrUpdate(...)` + `PollUntilDone` — rate-limited + metrics

**`UnassignPrivateIpAddressesVMSS`** (mirrors `AssignPrivateIpAddressesVMSS`):
1. `c.virtualMachineScaleSetVMs.Get(...)` with `InstanceViewTypesInstanceView`
2. Find NIC config by `interfaceName`; filter IP configurations the same way
3. Nil out `StorageProfile.ImageReference` (avoids gallery permissions error, see comment in existing code)
4. `c.virtualMachineScaleSetVMs.BeginUpdate(...)` + `PollUntilDone`

---

## Step 6 — Mock (`pkg/azure/api/mock/mock.go`)

Add `UnassignPrivateIpAddressesVM` and `UnassignPrivateIpAddressesVMSS` to the `Operation` enum. Implement by removing matching addresses from the in-memory `instances` map (inverse of `AssignPrivateIpAddressesVMSS`).

---

## Step 7 — Fix `PrepareIPRelease` (`pkg/azure/ipam/node.go:61`)

Pattern mirrors Alibaba (`pkg/alibabacloud/eni/node.go:325`). Primary IPs are excluded from `iface.Addresses` at parse time when `usePrimary=false` (`api.go:335`), so no special primary-guard needed here.

```go
func (n *Node) PrepareIPRelease(excessIPs int, scopedLog *slog.Logger) *ipam.ReleaseAction {
    r := &ipam.ReleaseAction{}
    requiredIfaceName := n.k8sObj.Spec.Azure.InterfaceName
    usedIPs := n.k8sObj.Status.IPAM.Used

    n.manager.mutex.RLock()
    defer n.manager.mutex.RUnlock()

    n.manager.instances.ForeachInterface(n.node.InstanceID(), func(_, _ string, obj ipamTypes.Interface) error {
        iface, ok := obj.(*types.AzureInterface)
        if !ok {
            return nil
        }
        if requiredIfaceName != "" && iface.Name != requiredIfaceName {
            return nil
        }
        var free []string
        for _, addr := range iface.Addresses {
            if _, used := usedIPs[addr.IP]; !used {
                free = append(free, addr.IP)
            }
        }
        maxRelease := min(len(free), excessIPs)
        if maxRelease > len(r.IPsToRelease) {
            poolID := ipamTypes.PoolID("")
            if len(iface.Addresses) > 0 {
                poolID = ipamTypes.PoolID(iface.Addresses[0].Subnet)
            }
            r.InterfaceID = iface.ID
            r.PoolID = poolID
            r.IPsToRelease = free[:maxRelease]
        }
        return nil
    })
    return r
}
```

---

## Step 8 — Implement `ReleaseIPs` (`pkg/azure/ipam/node.go:73`)

```go
func (n *Node) ReleaseIPs(ctx context.Context, r *ipam.ReleaseAction) error {
    if len(r.IPsToRelease) == 0 {
        return nil
    }
    var iface *types.AzureInterface
    n.manager.mutex.RLock()
    n.manager.instances.ForeachInterface(n.node.InstanceID(), func(_, interfaceID string, obj ipamTypes.Interface) error {
        if interfaceID == r.InterfaceID {
            iface, _ = obj.(*types.AzureInterface)
        }
        return nil
    })
    n.manager.mutex.RUnlock()
    if iface == nil {
        return fmt.Errorf("interface %s not found for instance %s", r.InterfaceID, n.node.InstanceID())
    }
    if iface.GetVMScaleSetName() == "" {
        return n.manager.api.UnassignPrivateIpAddressesVM(ctx, iface.Name, r.IPsToRelease)
    }
    return n.manager.api.UnassignPrivateIpAddressesVMSS(ctx, iface.GetVMID(), iface.GetVMScaleSetName(), iface.Name, r.IPsToRelease)
}
```

---

## Step 9 — Tests (`pkg/azure/ipam/node_test.go`)

Table-driven tests using the existing mock API (`pkg/azure/api/mock`), following the pattern in `pkg/azure/ipam/ipam_test.go`:

- `PrepareIPRelease` selects the right interface and IPs when excess > 0
- `PrepareIPRelease` returns empty action when all IPs are in use
- `PrepareIPRelease` respects `requiredIfaceName` from spec
- `ReleaseIPs` calls through to mock API and removes expected addresses
- `ReleaseIPs` is a no-op when `IPsToRelease` is empty

---

## Verification

```bash
CGO_ENABLED=0 go test -mod=vendor -vet=all ./pkg/azure/...
CGO_ENABLED=0 go test -mod=vendor -vet=all ./pkg/ipam/allocator/azure/...
# operator/pkg/ipam/azure.go requires the build tag:
CGO_ENABLED=0 go test -mod=vendor -vet=all -tags ipam_provider_azure ./operator/pkg/ipam/...
```
