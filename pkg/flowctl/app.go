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
	"github.com/spf13/cobra"
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
	}
	Detach struct {
		Netns string
		Name  string
	}
}{}

func NewCommandMeterAttach() *cobra.Command {
	cmd := &cobra.Command{
		Use: "attach",
		RunE: func(cmd *cobra.Command, args []string) error {
			println("hoge")
			return nil
		},
	}
	cmd.Flags().BoolVarP(&cliOptMeter.Attach.Override, "override", "o", true,
		"Override current ebpf bytecode")
	cmd.Flags().StringVar(&cliOptMeter.Attach.Name, "name", "",
		"Target interface name")
	cmd.Flags().StringVar(&cliOptMeter.Attach.Netns, "netns", "",
		"Target interface network namespace name")
	return cmd
}

func NewCommandMeterDetach() *cobra.Command {
	cmd := &cobra.Command{
		Use: "detach",
		RunE: func(cmd *cobra.Command, args []string) error {
			println("hoge")
			return nil
		},
	}
	cmd.Flags().StringVar(&cliOptMeter.Detach.Name, "name", "",
		"Target interface name")
	cmd.Flags().StringVar(&cliOptMeter.Detach.Netns, "netns", "",
		"Target interface network namespace name")
	return cmd
}
