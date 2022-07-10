/*
Copyright 2022 Hiroki Shirokura.
Copyright 2022 Keio University.
Copyright 2022 Wide Project.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package ebpfmap

import (
	"fmt"
	"math"

	"github.com/cilium/ebpf"
	"github.com/wide-vsix/linux-flow-exporter/pkg/ipfix"
	"github.com/wide-vsix/linux-flow-exporter/pkg/util"
)

const (
	mapName = "flow_stats"
	mapType = ebpf.PerCPUHash
)

type FlowKey struct {
	Ifindex uint32
	Saddr   uint32
	Daddr   uint32
	Sport   uint16
	Dport   uint16
	Proto   uint8
}

type FlowVal struct {
	FlowPkts             uint32 `json:"cnt"`
	FlowBytes            uint32 `json:"data_bytes"`
	FlowStartMilliSecond uint64 `json:"flow_start_msec"`
	FlowEndMilliSecond   uint64 `json:"flow_end_msec"`
	Finished             uint8
}

type Flow struct {
	Key FlowKey
	Val FlowVal
}

func (k FlowKey) String() string {
	saddr := util.ConvertUint32ToIP(k.Saddr)
	daddr := util.ConvertUint32ToIP(k.Daddr)
	return fmt.Sprintf("%d/%d/%s:%d/%s:%d",
		k.Ifindex,
		k.Proto,
		saddr.String(),
		k.Sport,
		daddr.String(),
		k.Dport,
	)
}

func (v *FlowVal) Merge(src FlowVal) {
	v.FlowPkts += src.FlowPkts
	v.FlowBytes += src.FlowBytes
	if v.FlowStartMilliSecond == 0 {
		v.FlowStartMilliSecond = math.MaxUint64
	}
	if src.FlowStartMilliSecond != 0 &&
		src.FlowStartMilliSecond <= v.FlowStartMilliSecond {
		v.FlowStartMilliSecond = src.FlowStartMilliSecond
	}
	if src.FlowEndMilliSecond != 0 &&
		src.FlowEndMilliSecond >= v.FlowEndMilliSecond {
		v.FlowEndMilliSecond = src.FlowEndMilliSecond
	}
	if src.Finished != 0 {
		v.Finished = 1
	}
}

func GetMapIDsByNameType(mapName string, mapType ebpf.MapType) ([]ebpf.MapID, error) {
	ids := []ebpf.MapID{}
	for id := ebpf.MapID(0); ; {
		var err error
		id, err = ebpf.MapGetNextID(ebpf.MapID(id))
		if err != nil {
			break
		}
		m, err := ebpf.NewMapFromID(id)
		if err != nil {
			return nil, err
		}
		info, err := m.Info()
		if err != nil {
			return nil, err
		}
		if info.Name != mapName || info.Type != mapType {
			continue
		}
		ids = append(ids, id)
	}
	return ids, nil
}

func Dump() ([]Flow, error) {
	ids, err := GetMapIDsByNameType(mapName, mapType)
	if err != nil {
		return nil, err
	}

	flows := []Flow{}
	for _, id := range ids {
		m, err := ebpf.NewMapFromID(id)
		if err != nil {
			return nil, err
		}

		key := FlowKey{}
		perCpuVals := []FlowVal{}
		entries := m.Iterate()
		for entries.Next(&key, &perCpuVals) {
			val := FlowVal{}
			for _, perCpuVal := range perCpuVals {
				val.Merge(perCpuVal)
			}
			flows = append(flows, Flow{key, val})
		}
		if err := entries.Err(); err != nil {
			panic(err)
		}
	}
	return flows, nil
}

func Delete(key FlowKey) error {
	ids, err := GetMapIDsByNameType(mapName, mapType)
	if err != nil {
		return err
	}
	for _, id := range ids {
		m, err := ebpf.NewMapFromID(id)
		if err != nil {
			return err
		}
		if err := m.Delete(key); err != nil {
			return err
		}
	}
	return nil
}

func DeleteAll() error {
	ids, err := GetMapIDsByNameType(mapName, mapType)
	if err != nil {
		return err
	}
	for _, id := range ids {
		m, err := ebpf.NewMapFromID(id)
		if err != nil {
			return err
		}
		key := FlowKey{}
		perCpuVals := []FlowVal{}
		entries := m.Iterate()
		for entries.Next(&key, &perCpuVals) {
			if err := m.Delete(key); err != nil {
				return err
			}
		}
	}
	return nil
}

func ToIpfixFlowFile(ebflows []Flow) (*ipfix.FlowFile, error) {
	flows := []ipfix.Flow{}
	for _, ebflow := range ebflows {
		s, err := util.KtimeToRealMilli(ebflow.Val.FlowStartMilliSecond / 1000000)
		if err != nil {
			return nil, err
		}
		e, err := util.KtimeToRealMilli(ebflow.Val.FlowEndMilliSecond / 1000000)
		if err != nil {
			return nil, err
		}

		flows = append(flows, ipfix.Flow{
			IpVersion:                4,
			SourceIPv4Address:        util.BS32(ebflow.Key.Saddr),
			DestinationIPv4Address:   util.BS32(ebflow.Key.Daddr),
			ProtocolIdentifier:       ebflow.Key.Proto,
			SourceTransportPort:      ebflow.Key.Sport,
			DestinationTransportPort: ebflow.Key.Dport,
			OctetDeltaCount:          uint64(ebflow.Val.FlowBytes),
			PacketDeltaCount:         uint64(ebflow.Val.FlowPkts),
			FlowStartMilliseconds:    s,
			FlowEndMilliseconds:      e,
		})
	}

	flowFile := &ipfix.FlowFile{
		FlowSets: []struct {
			TemplateID uint16       `yaml:"templateId"`
			Flows      []ipfix.Flow `yaml:"flows"`
		}{
			{
				TemplateID: uint16(1004),
				Flows:      flows,
			},
		},
	}
	return flowFile, nil
}
