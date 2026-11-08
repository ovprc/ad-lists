// SPDX-License-Identifier: GPL-3.0-or-later
// MinTun adapter for SagerNet/sing-box v1.15.0-alpha.13 (824dbcfb4dd0a95921840b1737b950cde590241e).
// Compiled inside experimental/libbox; upstream source is otherwise unmodified.
package libbox

import (
    "context"
    "errors"
    "sync"

    box "github.com/sagernet/sing-box"
    "github.com/sagernet/sing-box/adapter"
    "github.com/sagernet/sing-box/option"
    "github.com/sagernet/sing/service"
)

// MintunSetup deliberately omits Setup's stderr redirection, config snapshots and
// diagnostic/power reporting. Private profiles never become crash-report files.
func MintunSetup(options *SetupOptions) {
    options.Debug = false
    options.LogMaxLines = 0
    options.PowerReportEnabled = false
    options.OomKillerEnabled = false
    options.OomKillerDisabled = true
    applySetupOptions(options)
}

// MintunService embeds the real core behind the upstream libbox platform adapter.
// Android VpnService owns its lifetime independently from NativeActivity.
type MintunService struct {
    access sync.Mutex
    instance *box.Box
    cancel context.CancelFunc
    started bool
}

func NewMintunService(configContent string, platform PlatformInterface) (*MintunService, error) {
    ctx, cancel := context.WithCancel(baseContext(platform))
    platformWrapper := &platformInterfaceWrapper{iif: platform}
    service.MustRegister[adapter.PlatformInterface](ctx, platformWrapper)
    options, err := parseConfig(ctx, configContent)
    if err != nil {
        cancel()
        return nil, err
    }
    options.Log = &option.LogOptions{Disabled: true}
    instance, err := box.New(box.Options{Context: ctx, Options: options})
    if err != nil {
        cancel()
        return nil, err
    }
    // Android's public VPN API cannot expose the neighbor table. Do not silently
    // ignore source-MAC rules as upstream's optional resolver startup would do.
    if instance.Router().NeedFindNeighbor() {
        instance.Close()
        cancel()
        return nil, errors.New("source-MAC and neighbor-table rules require root and are unavailable in Android VpnService")
    }
    return &MintunService{instance: instance, cancel: cancel}, nil
}

func (s *MintunService) Start() error {
    s.access.Lock()
    defer s.access.Unlock()
    if s.instance == nil {
        return context.Canceled
    }
    if s.started {
        return nil
    }
    if err := s.instance.Start(); err != nil {
        s.cancel()
        s.instance = nil // Box.Start closes its own partially started scope on error.
        return err
    }
    s.started = true
    return nil
}

func (s *MintunService) Close() error {
    s.access.Lock()
    defer s.access.Unlock()
    if s.instance == nil {
        return nil
    }
    s.cancel()
    err := s.instance.Close()
    s.instance = nil
    s.started = false
    return err
}
