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

package flowctl

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/wide-vsix/linux-flow-exporter/pkg/goroute2"
	"github.com/wide-vsix/linux-flow-exporter/pkg/util"
)

func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use: "flowctl",
	}
	cmd.AddCommand(NewCommandDump())
	cmd.AddCommand(NewCommandFlush())
	cmd.AddCommand(NewCommandIpfix())
	cmd.AddCommand(NewCommandPrometheus())
	cmd.AddCommand(NewCommandMeter())
	cmd.AddCommand(util.NewCmdCompletion(cmd))
	return cmd
}

func NewCommandMeter() *cobra.Command {
	cmd := &cobra.Command{
		Use: "meter",
	}
	cmd.AddCommand(NewCommandMeterAttach())
	cmd.AddCommand(NewCommandMeterDetach())
	return cmd
}

var cliOptMeter = struct {
	Attach struct {
		Override bool
		Netns    string
		Name     string
		Bpf      string
		Section  string
		Pref     uint
		Chain    uint
		Handle   uint
	}
	Detach struct {
		Netns  string
		Name   string
		Pref   uint
		Chain  uint
		Handle uint
	}
}{}

func NewCommandMeterAttach() *cobra.Command {
	cmd := &cobra.Command{
		Use: "attach",
		RunE: func(cmd *cobra.Command, args []string) error {
			netnsPreCmd := ""
			if cliOptMeter.Attach.Netns != "" {
				netnsPreCmd = fmt.Sprintf("ip netns exec %s", cliOptMeter.Attach.Netns)
			}

			// Enable cls act if it's disabled
			clsActIsEnabled, err := goroute2.ClsActIsEnabled(cliOptMeter.Attach.Netns,
				cliOptMeter.Attach.Name)
			if err != nil {
				return err
			}
			if !clsActIsEnabled {
				if _, err := util.LocalExecutef("%s tc qdisc add dev %s clsact",
					netnsPreCmd, cliOptMeter.Attach.Name); err != nil {
					return err
				}
			}

			// Delete existing rule
			if cliOptMeter.Attach.Override {
				rules, err := goroute2.ListTcFilterRules(cliOptMeter.Attach.Netns,
					cliOptMeter.Attach.Name)
				if err != nil {
					return err
				}
				for _, rule := range rules {
					if rule.Pref == cliOptMeter.Attach.Pref &&
						rule.Chain == cliOptMeter.Attach.Chain &&
						rule.Options.Handle == fmt.Sprintf("0x%x", cliOptMeter.Attach.Handle) {
						if _, err := util.LocalExecutef("%s tc filter del dev %s egress "+
							"pref %d chain %d handle 0x%x bpf", netnsPreCmd,
							cliOptMeter.Attach.Name,
							cliOptMeter.Attach.Pref,
							cliOptMeter.Attach.Chain, cliOptMeter.Attach.Handle,
						); err != nil {
							return err
						}
					}
				}
			}

			// Install rule
			//
			// [EXAMPLE]
			// tc filter add dev eth1 egress \
			//   pref 100 chain 10 handle 0xA \
			//   bpf obj ./cmd/ebpflow/filter.bpf.o section tc-egress
			if _, err := util.LocalExecutef("%s tc filter add dev %s egress "+
				"pref %d chain %d handle 0x%x "+
				"bpf obj %s section %s", netnsPreCmd, cliOptMeter.Attach.Name,
				cliOptMeter.Attach.Pref, cliOptMeter.Attach.Chain,
				cliOptMeter.Attach.Handle,
				cliOptMeter.Attach.Bpf, cliOptMeter.Attach.Section,
			); err != nil {
				return err
			}
			return nil
		},
	}
	cmd.Flags().BoolVarP(&cliOptMeter.Attach.Override, "override", "o", true,
		"Override current ebpf bytecode")
	cmd.Flags().StringVarP(&cliOptMeter.Attach.Name, "name", "n", "",
		"Target interface name")
	cmd.Flags().StringVar(&cliOptMeter.Attach.Netns, "netns", "",
		"Target interface network namespace name")
	cmd.Flags().StringVar(&cliOptMeter.Attach.Bpf, "bpf",
		"cmd/ebpflow/filter.bpf.o", "Target bpf byte code file name")
	cmd.Flags().StringVar(&cliOptMeter.Attach.Section, "section",
		"tc-egress", "Target section name of bpf byte code")
	cmd.Flags().UintVar(&cliOptMeter.Attach.Pref, "pref", 100,
		"Target preference idx of tc-egress")
	cmd.Flags().UintVar(&cliOptMeter.Attach.Chain, "chain", 0,
		"Target chain idx of tc-egress")
	cmd.Flags().UintVar(&cliOptMeter.Attach.Handle, "handle", 1,
		"Target handle idx of chain of tc-egress")
	return cmd
}

func NewCommandMeterDetach() *cobra.Command {
	cmd := &cobra.Command{
		Use: "detach",
		RunE: func(cmd *cobra.Command, args []string) error {
			netnsPreCmd := ""
			if cliOptMeter.Detach.Netns != "" {
				netnsPreCmd = fmt.Sprintf("ip netns exec %s", cliOptMeter.Detach.Netns)
			}

			// Delete rule if exist
			rules, err := goroute2.ListTcFilterRules(cliOptMeter.Detach.Netns,
				cliOptMeter.Detach.Name)
			if err != nil {
				return err
			}
			for _, rule := range rules {
				if rule.Pref == cliOptMeter.Detach.Pref &&
					rule.Chain == cliOptMeter.Detach.Chain &&
					rule.Options.Handle == fmt.Sprintf("0x%x", cliOptMeter.Detach.Handle) {
					if _, err := util.LocalExecutef("%s tc filter del dev %s egress "+
						"pref %d chain %d handle 0x%x bpf", netnsPreCmd,
						cliOptMeter.Detach.Name,
						cliOptMeter.Detach.Pref,
						cliOptMeter.Detach.Chain, cliOptMeter.Detach.Handle,
					); err != nil {
						return err
					}
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&cliOptMeter.Detach.Name, "name", "n", "",
		"Target interface name")
	cmd.Flags().StringVar(&cliOptMeter.Detach.Netns, "netns", "",
		"Target interface network namespace name")
	cmd.Flags().UintVar(&cliOptMeter.Detach.Pref, "pref", 100,
		"Target preference idx of tc-egress")
	cmd.Flags().UintVar(&cliOptMeter.Detach.Chain, "chain", 0,
		"Target chain idx of tc-egress")
	cmd.Flags().UintVar(&cliOptMeter.Detach.Handle, "handle", 1,
		"Target handle idx of chain of tc-egress")
	return cmd
}
