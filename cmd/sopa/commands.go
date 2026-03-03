package main

import (
	"fmt"
	"strings"

	adws "github.com/Macmod/sopa"
	"github.com/spf13/cobra"
)

func newQueryCmd(common *commonOptions) *cobra.Command {
	var filter string
	var attrsCSV string
	var scope int
	var maxPrint int

	cmd := &cobra.Command{
		Use:     "query",
		Short:   "Enumerate objects via WS-Enumeration",
		Aliases: []string{"q"},
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := normalizeCommonOptions(common); err != nil {
				return err
			}
			p := NewPrinter(cmd.OutOrStdout(), common.noColor, common.jsonOutput)
			attrs := splitCSV(attrsCSV)
			return withClient(cmd, *common, func(client *adws.WSClient) error {
				items, err := client.Query(common.baseDN, filter, attrs, scope)
				if err != nil {
					return err
				}
				p.Successf("Found %d objects\n", len(items))
				for i := 0; i < len(items); i++ {
					p.PrintItem(&items[i])
					if maxPrint > 0 && i+1 >= maxPrint {
						break
					}
				}
				return nil
			})
		},
	}

	cmd.Flags().StringVar(&filter, "filter", "(objectClass=*)", "LDAP filter")
	cmd.Flags().StringVar(&attrsCSV, "attrs", "distinguishedName,cn,sAMAccountName", "Comma-separated attributes")
	cmd.Flags().IntVar(&scope, "scope", 2, "Search scope: 0=Base 1=Onelevel 2=Subtree")
	cmd.Flags().IntVar(&maxPrint, "max", 0, "Max objects to print (0=all)")
	return cmd
}

func newGetCmd(common *commonOptions) *cobra.Command {
	var dn string
	var attrsCSV string

	cmd := &cobra.Command{
		Use:     "get",
		Short:   "Get an object by DN via WS-Transfer Get",
		Aliases: []string{"g"},
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := normalizeCommonOptions(common); err != nil {
				return err
			}
			p := NewPrinter(cmd.OutOrStdout(), common.noColor, common.jsonOutput)
			dn = strings.TrimSpace(dn)
			if dn == "" {
				return fmt.Errorf("--dn is required")
			}

			attrs := splitCSV(attrsCSV)
			return withClient(cmd, *common, func(client *adws.WSClient) error {
				item, err := client.WSTransferGet(dn, attrs)
				if err != nil {
					return err
				}
				p.PrintItem(item)
				return nil
			})
		},
	}

	cmd.Flags().StringVar(&dn, "dn", "", "Distinguished Name to get")
	cmd.Flags().StringVar(&attrsCSV, "attrs", "distinguishedName,cn,sAMAccountName", "Comma-separated attributes")
	_ = cmd.MarkFlagRequired("dn")
	return cmd
}

func newDeleteCmd(common *commonOptions) *cobra.Command {
	var dn string

	cmd := &cobra.Command{
		Use:     "delete",
		Short:   "Delete an object by DN via WS-Transfer",
		Aliases: []string{"del", "rm"},
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := normalizeCommonOptions(common); err != nil {
				return err
			}
			p := NewPrinter(cmd.OutOrStdout(), common.noColor, common.jsonOutput)
			dn = strings.TrimSpace(dn)
			if dn == "" {
				return fmt.Errorf("--dn is required")
			}
			return withClient(cmd, *common, func(client *adws.WSClient) error {
				if err := client.WSTransferDelete(dn); err != nil {
					return err
				}
				if common.jsonOutput {
					p.PrintJSON(map[string]any{"status": "ok", "op": "delete", "dn": dn})
				} else {
					p.Donef("Deleted %s\n", dn)
				}
				return nil
			})
		},
	}

	cmd.Flags().StringVar(&dn, "dn", "", "Distinguished Name to delete (DANGEROUS)")
	_ = cmd.MarkFlagRequired("dn")
	return cmd
}

func newCreateCmd(common *commonOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "create",
		Short:   "Create AD objects via WS-Transfer Create (IMDA AddRequest)",
		Aliases: []string{"c"},
	}

	cmd.AddCommand(newCreateComputerCmd(common))
	cmd.AddCommand(newCreateUserCmd(common))
	cmd.AddCommand(newCreateGroupCmd(common))
	cmd.AddCommand(newCreateOUCmd(common))
	cmd.AddCommand(newCreateContainerCmd(common))
	cmd.AddCommand(newCreateCustomCmd(common))
	return cmd
}

func newSetPasswordCmd(common *commonOptions) *cobra.Command {
	var dn string
	var partitionDN string
	var newPassword string

	cmd := &cobra.Command{
		Use:   "set-password",
		Short: "Set the password for an account (MS-ADCAP SetPassword)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := normalizeCommonOptions(common); err != nil {
				return err
			}
			p := NewPrinter(cmd.OutOrStdout(), common.noColor, common.jsonOutput)
			dn = strings.TrimSpace(dn)
			partitionDN = strings.TrimSpace(partitionDN)
			if dn == "" {
				return fmt.Errorf("--dn is required")
			}
			if partitionDN == "" {
				partitionDN = domainToDN(common.domain)
			}
			if newPassword == "" || strings.TrimSpace(newPassword) == "" {
				return fmt.Errorf("--new is required")
			}
			return withClient(cmd, *common, func(client *adws.WSClient) error {
				if err := client.ADCAPSetPassword(dn, partitionDN, newPassword); err != nil {
					return err
				}
				if common.jsonOutput {
					p.PrintJSON(map[string]any{"status": "ok", "op": "set-password", "dn": dn})
				} else {
					p.Donef("Password set for %s\n", dn)
				}
				return nil
			})
		},
	}

	cmd.Flags().StringVar(&dn, "dn", "", "Account distinguished name")
	cmd.Flags().StringVar(&partitionDN, "partition-dn", "", "Partition naming context DN (default: derived from --domain)")
	cmd.Flags().StringVar(&newPassword, "new", "", "New password")
	_ = combineErrors(cmd.MarkFlagRequired("dn"), cmd.MarkFlagRequired("new"))
	return cmd
}

func newChangePasswordCmd(common *commonOptions) *cobra.Command {
	var dn string
	var partitionDN string
	var oldPassword string
	var newPassword string

	cmd := &cobra.Command{
		Use:   "change-password",
		Short: "Change the password for an account (MS-ADCAP ChangePassword)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := normalizeCommonOptions(common); err != nil {
				return err
			}
			p := NewPrinter(cmd.OutOrStdout(), common.noColor, common.jsonOutput)
			dn = strings.TrimSpace(dn)
			partitionDN = strings.TrimSpace(partitionDN)
			if dn == "" {
				return fmt.Errorf("--dn is required")
			}
			if partitionDN == "" {
				partitionDN = domainToDN(common.domain)
			}
			if oldPassword == "" || strings.TrimSpace(oldPassword) == "" {
				return fmt.Errorf("--old is required")
			}
			if newPassword == "" || strings.TrimSpace(newPassword) == "" {
				return fmt.Errorf("--new is required")
			}
			return withClient(cmd, *common, func(client *adws.WSClient) error {
				if err := client.ADCAPChangePassword(dn, partitionDN, oldPassword, newPassword); err != nil {
					return err
				}
				if common.jsonOutput {
					p.PrintJSON(map[string]any{"status": "ok", "op": "change-password", "dn": dn})
				} else {
					p.Donef("Password changed for %s\n", dn)
				}
				return nil
			})
		},
	}

	cmd.Flags().StringVar(&dn, "dn", "", "Account distinguished name")
	cmd.Flags().StringVar(&partitionDN, "partition-dn", "", "Partition naming context DN (default: derived from --domain)")
	cmd.Flags().StringVar(&oldPassword, "old", "", "Old password")
	cmd.Flags().StringVar(&newPassword, "new", "", "New password")
	_ = combineErrors(cmd.MarkFlagRequired("dn"), cmd.MarkFlagRequired("old"), cmd.MarkFlagRequired("new"))
	return cmd
}

func newTranslateNameCmd(common *commonOptions) *cobra.Command {
	var formatOffered string
	var formatDesired string

	cmd := &cobra.Command{
		Use:   "translate-name <name> [name...]",
		Short: "Translate names between DistinguishedName and CanonicalName (MS-ADCAP TranslateName)",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := normalizeCommonOptions(common); err != nil {
				return err
			}
			p := NewPrinter(cmd.OutOrStdout(), common.noColor, common.jsonOutput)
			formatOffered = strings.TrimSpace(formatOffered)
			formatDesired = strings.TrimSpace(formatDesired)
			return withClient(cmd, *common, func(client *adws.WSClient) error {
				results, err := client.ADCAPTranslateName(formatOffered, formatDesired, args)
				if err != nil {
					return err
				}
				if len(results) != len(args) {
					p.Infof("Warning: result count %d does not match input count %d\n", len(results), len(args))
				}
				for i := 0; i < len(results) && i < len(args); i++ {
					r := results[i]
					if r.Result == 0 {
						if common.jsonOutput {
							p.PrintJSON(map[string]any{"status": "ok", "input": args[i], "output": strings.TrimSpace(r.Name), "code": 0})
						} else {
							p.Donef("%s -> %s\n", args[i], r.Name)
						}
					} else {
						if common.jsonOutput {
							p.PrintJSON(map[string]any{"status": "error", "input": args[i], "output": nil, "code": r.Result})
						} else {
							p.Fprintf("%s -> (error %d)\n", args[i], r.Result)
						}
					}
				}
				return nil
			})
		},
	}

	cmd.Flags().StringVar(&formatOffered, "offered", "DistinguishedName", "Offered format: DistinguishedName or CanonicalName")
	cmd.Flags().StringVar(&formatDesired, "desired", "CanonicalName", "Desired format: DistinguishedName or CanonicalName")
	return cmd
}

func newGroupsCmd(common *commonOptions) *cobra.Command {
	var dn string
	var membership bool
	var authz bool

	cmd := &cobra.Command{
		Use:   "groups",
		Short: "List groups for a principal DN (membership and/or authorization groups)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := normalizeCommonOptions(common); err != nil {
				return err
			}
			p := NewPrinter(cmd.OutOrStdout(), common.noColor, common.jsonOutput)
			dn = strings.TrimSpace(dn)
			if dn == "" {
				return fmt.Errorf("--dn is required")
			}

			// If neither flag is specified, do both.
			doMembership := membership
			doAuthz := authz
			if !doMembership && !doAuthz {
				doMembership = true
				doAuthz = true
			}

			return withClient(cmd, *common, func(client *adws.WSClient) error {
				if doMembership {
					items, err := client.PrincipalGroupMembership(dn)
					if err != nil {
						return err
					}
					p.Successf("Membership groups: %d\n", len(items))
					for i := range items {
						if common.jsonOutput {
							p.PrintJSON(map[string]any{"dn": items[i].DistinguishedName, "type": "membership"})
						} else {
							p.Donef("%s\n", items[i].DistinguishedName)
						}
					}
				}

				if doAuthz {
					items, err := client.PrincipalAuthorizationGroups(dn)
					if err != nil {
						return err
					}
					p.Successf("Authorization groups: %d\n", len(items))
					for i := range items {
						if common.jsonOutput {
							p.PrintJSON(map[string]any{"dn": items[i].DistinguishedName, "type": "authz"})
						} else {
							p.Donef("%s\n", items[i].DistinguishedName)
						}
					}
				}

				return nil
			})
		},
	}

	cmd.Flags().StringVar(&dn, "dn", "", "Principal distinguished name")
	cmd.Flags().BoolVar(&membership, "membership", false, "Show principal group membership (MS-ADCAP GetADPrincipalGroupMembership)")
	cmd.Flags().BoolVar(&authz, "authz", false, "Show security-enabled authorization groups (MS-ADCAP GetADPrincipalAuthorizationGroup)")
	_ = cmd.MarkFlagRequired("dn")
	return cmd
}

func newGroupMembersCmd(common *commonOptions) *cobra.Command {
	var groupDN string
	var partitionDN string
	var recursive bool

	cmd := &cobra.Command{
		Use:     "members",
		Aliases: []string{"group-members"},
		Short:   "List members of a group (MS-ADCAP GetADGroupMember)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := normalizeCommonOptions(common); err != nil {
				return err
			}
			p := NewPrinter(cmd.OutOrStdout(), common.noColor, common.jsonOutput)
			groupDN = strings.TrimSpace(groupDN)
			partitionDN = strings.TrimSpace(partitionDN)
			if groupDN == "" {
				return fmt.Errorf("--dn is required")
			}
			if partitionDN == "" {
				partitionDN = domainToDN(common.domain)
			}

			return withClient(cmd, *common, func(client *adws.WSClient) error {
				members, err := client.ADCAPGetADGroupMember(groupDN, partitionDN, recursive)
				if err != nil {
					return err
				}
				p.Successf("Members: %d\n", len(members))
				for _, m := range members {
					if common.jsonOutput {
						p.PrintJSON(map[string]any{
							"dn":             strings.TrimSpace(m.DistinguishedName),
							"name":           strings.TrimSpace(m.Name),
							"samAccountName": strings.TrimSpace(m.SamAccountName),
						})
					} else {
						label := strings.TrimSpace(m.DistinguishedName)
						if label == "" {
							label = strings.TrimSpace(m.Name)
						}
						if label == "" {
							label = strings.TrimSpace(m.SamAccountName)
						}
						p.Donef("%s\n", label)
					}
				}
				return nil
			})
		},
	}

	cmd.Flags().StringVar(&groupDN, "dn", "", "Group distinguished name")
	cmd.Flags().StringVar(&partitionDN, "partition-dn", "", "Partition naming context DN (default: derived from --domain)")
	cmd.Flags().BoolVar(&recursive, "recursive", false, "Recursively include members of child groups")
	_ = cmd.MarkFlagRequired("dn")
	return cmd
}

func newOptFeatureCmd(common *commonOptions) *cobra.Command {
	var distinguishedName string
	var featureID string
	var enable bool

	cmd := &cobra.Command{
		Use:   "optfeature",
		Short: "Enable/disable an optional feature (MS-ADCAP ChangeOptionalFeature)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := normalizeCommonOptions(common); err != nil {
				return err
			}
			p := NewPrinter(cmd.OutOrStdout(), common.noColor, common.jsonOutput)
			distinguishedName = strings.TrimSpace(distinguishedName)
			featureID = strings.TrimSpace(featureID)
			if distinguishedName == "" {
				distinguishedName = domainToDN(common.domain)
			}
			if featureID == "" {
				return fmt.Errorf("--feature-id is required")
			}

			verb := "disable"
			if enable {
				verb = "enable"
			}
			p.Infof("Requesting %s optional feature %s on %s\n", verb, featureID, distinguishedName)

			return withClient(cmd, *common, func(client *adws.WSClient) error {
				if err := client.ADCAPChangeOptionalFeature(distinguishedName, enable, featureID); err != nil {
					return err
				}
				if common.jsonOutput {
					p.PrintJSON(map[string]any{"status": "ok", "op": "optfeature", "dn": distinguishedName})
				} else {
					p.Donef("OK\n")
				}
				return nil
			})
		},
	}

	cmd.Flags().StringVar(&distinguishedName, "dn", "", "Naming context DN (default: derived from --domain)")
	cmd.Flags().StringVar(&featureID, "feature-id", "", "Feature GUID (e.g. for Recycle Bin)")
	cmd.Flags().BoolVar(&enable, "enable", false, "Enable the feature (default: disable)")
	_ = cmd.MarkFlagRequired("feature-id")
	return cmd
}

func newInfoCmd(common *commonOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "info",
		Short: "Topology info (MS-ADCAP TopologyManagement)",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Show ADWS Custom Action Protocol version (MS-ADCAP GetVersion)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := normalizeCommonOptions(common); err != nil {
				return err
			}
			p := NewPrinter(cmd.OutOrStdout(), common.noColor, common.jsonOutput)
			return withClient(cmd, *common, func(client *adws.WSClient) error {
				ver, err := client.ADCAPGetVersion()
				if err != nil {
					return err
				}
				if common.jsonOutput {
					p.PrintJSON(map[string]any{"major": ver.Major, "minor": ver.Minor, "string": strings.TrimSpace(ver.String)})
				} else {
					p.Donef("Version: %d.%d (%s)\n", ver.Major, ver.Minor, strings.TrimSpace(ver.String))
				}
				return nil
			})
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "domain",
		Short: "Show domain info (MS-ADCAP GetADDomain)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := normalizeCommonOptions(common); err != nil {
				return err
			}
			p := NewPrinter(cmd.OutOrStdout(), common.noColor, common.jsonOutput)
			return withClient(cmd, *common, func(client *adws.WSClient) error {
				d, err := client.ADCAPGetADDomain()
				if err != nil {
					return err
				}
				if common.jsonOutput {
					p.PrintJSON(map[string]any{
						"distinguishedName":    strings.TrimSpace(d.DistinguishedName),
						"dnsRoot":              strings.TrimSpace(d.DNSRoot),
						"netBIOSName":          strings.TrimSpace(d.NetBIOSName),
						"forest":               strings.TrimSpace(d.Forest),
						"domainMode":           d.DomainMode,
						"pdcEmulator":          strings.TrimSpace(d.PDCEmulator),
						"ridMaster":            strings.TrimSpace(d.RIDMaster),
						"infrastructureMaster": strings.TrimSpace(d.InfrastructureMaster),
					})
				} else {
					p.Donef("DistinguishedName: %s\n", strings.TrimSpace(d.DistinguishedName))
					p.Donef("DNSRoot: %s\n", strings.TrimSpace(d.DNSRoot))
					p.Donef("NetBIOSName: %s\n", strings.TrimSpace(d.NetBIOSName))
					p.Donef("Forest: %s\n", strings.TrimSpace(d.Forest))
					p.Donef("DomainMode: %d\n", d.DomainMode)
					p.Donef("PDCEmulator: %s\n", strings.TrimSpace(d.PDCEmulator))
					p.Donef("RIDMaster: %s\n", strings.TrimSpace(d.RIDMaster))
					p.Donef("InfrastructureMaster: %s\n", strings.TrimSpace(d.InfrastructureMaster))
				}
				return nil
			})
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "forest",
		Short: "Show forest info (MS-ADCAP GetADForest)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := normalizeCommonOptions(common); err != nil {
				return err
			}
			p := NewPrinter(cmd.OutOrStdout(), common.noColor, common.jsonOutput)
			return withClient(cmd, *common, func(client *adws.WSClient) error {
				f, err := client.ADCAPGetADForest()
				if err != nil {
					return err
				}
				if common.jsonOutput {
					p.PrintJSON(map[string]any{
						"name":               strings.TrimSpace(f.Name),
						"rootDomain":         strings.TrimSpace(f.RootDomain),
						"forestMode":         f.ForestMode,
						"schemaMaster":       strings.TrimSpace(f.SchemaMaster),
						"domainNamingMaster": strings.TrimSpace(f.DomainNamingMaster),
						"domains":            len(f.Domains),
						"sites":              len(f.Sites),
						"globalCatalogs":     len(f.GlobalCatalogs),
					})
				} else {
					p.Donef("Name: %s\n", strings.TrimSpace(f.Name))
					p.Donef("RootDomain: %s\n", strings.TrimSpace(f.RootDomain))
					p.Donef("ForestMode: %d\n", f.ForestMode)
					p.Donef("SchemaMaster: %s\n", strings.TrimSpace(f.SchemaMaster))
					p.Donef("DomainNamingMaster: %s\n", strings.TrimSpace(f.DomainNamingMaster))
					p.Donef("Domains: %d\n", len(f.Domains))
					p.Donef("Sites: %d\n", len(f.Sites))
					p.Donef("GlobalCatalogs: %d\n", len(f.GlobalCatalogs))
				}
				return nil
			})
		},
	})

	cmd.AddCommand(newInfoDCsCmd(common))
	return cmd
}

func newInfoDCsCmd(common *commonOptions) *cobra.Command {
	var ntdsDNs []string

	cmd := &cobra.Command{
		Use:   "dcs",
		Short: "Show domain controller info (MS-ADCAP GetADDomainController)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := normalizeCommonOptions(common); err != nil {
				return err
			}
			p := NewPrinter(cmd.OutOrStdout(), common.noColor, common.jsonOutput)
			return withClient(cmd, *common, func(client *adws.WSClient) error {
				inputs := make([]string, 0, len(ntdsDNs))
				for _, dn := range ntdsDNs {
					dn = strings.TrimSpace(dn)
					if dn == "" {
						continue
					}
					inputs = append(inputs, dn)
				}
				if len(inputs) == 0 {
					// Discover nTDSDSA objects from the configuration NC.
					configDN := fmt.Sprintf("CN=Configuration,%s", domainToDN(common.domain))
					items, err := client.Query(configDN, "(objectClass=nTDSDSA)", []string{"distinguishedName"}, 2)
					if err != nil {
						return err
					}
					for i := range items {
						if strings.TrimSpace(items[i].DistinguishedName) == "" {
							continue
						}
						inputs = append(inputs, items[i].DistinguishedName)
					}
				}
				if len(inputs) == 0 {
					return fmt.Errorf("no nTDSDSA DNs found (provide --ntds-dn or ensure query access)")
				}

				res, err := client.ADCAPGetADDomainControllers(inputs)
				if err != nil {
					return err
				}
				p.Successf("DomainControllers: %d\n", len(res))
				for _, dc := range res {
					host := strings.TrimSpace(dc.HostName)
					if host == "" {
						host = strings.TrimSpace(dc.Name)
					}
					if common.jsonOutput {
						p.PrintJSON(map[string]any{
							"hostname": host,
							"site":     strings.TrimSpace(dc.Site),
							"ldapPort": dc.LdapPort,
							"sslPort":  dc.SslPort,
						})
					} else {
						site := strings.TrimSpace(dc.Site)
						if site != "" {
							p.Donef("%s (site=%s ldap=%d ssl=%d)\n", host, site, dc.LdapPort, dc.SslPort)
						} else {
							p.Donef("%s (ldap=%d ssl=%d)\n", host, dc.LdapPort, dc.SslPort)
						}
					}
				}
				return nil
			})
		},
	}

	cmd.Flags().StringArrayVar(&ntdsDNs, "ntds-dn", nil, "nTDSDSA distinguished name (repeatable; if omitted, auto-discovers from CN=Configuration)")
	return cmd
}

func newCreateComputerCmd(common *commonOptions) *cobra.Command {
	var name string
	var pass string
	var parentDN string

	cmd := &cobra.Command{
		Use:   "computer",
		Short: "Create a computer account",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := normalizeCommonOptions(common); err != nil {
				return err
			}
			p := NewPrinter(cmd.OutOrStdout(), common.noColor, common.jsonOutput)
			name = strings.TrimSpace(name)
			parentDN = strings.TrimSpace(parentDN)
			if name == "" {
				return fmt.Errorf("--name is required")
			}
			if pass == "" || strings.TrimSpace(pass) == "" {
				return fmt.Errorf("--pass is required")
			}
			if parentDN == "" {
				parentDN = fmt.Sprintf("CN=Computers,%s", common.baseDN)
			}

			cn := strings.TrimSuffix(name, "$")
			newDN := fmt.Sprintf("CN=%s,%s", cn, parentDN)
			p.Infof("Creating computer: %s\n", newDN)
			return withClient(cmd, *common, func(client *adws.WSClient) error {
				_, err := client.WSTransferAddComputer(parentDN, name, pass)
				if err != nil {
					return err
				}
				if common.jsonOutput {
					p.PrintJSON(map[string]any{"status": "ok", "op": "create", "dn": newDN})
				} else {
					p.Donef("Created %s\n", newDN)
				}
				return nil
			})
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "Computer name (e.g. PENTEST or PENTEST$)")
	cmd.Flags().StringVar(&pass, "pass", "", "Password to set for the computer account")
	cmd.Flags().StringVar(&parentDN, "parent-dn", "", "Parent container DN (default: CN=Computers,<basedn>)")
	_ = combineErrors(cmd.MarkFlagRequired("name"), cmd.MarkFlagRequired("pass"))
	return cmd
}

func newCreateUserCmd(common *commonOptions) *cobra.Command {
	var name string
	var pass string
	var parentDN string
	var enabled bool

	cmd := &cobra.Command{
		Use:   "user",
		Short: "Create a user account",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := normalizeCommonOptions(common); err != nil {
				return err
			}
			p := NewPrinter(cmd.OutOrStdout(), common.noColor, common.jsonOutput)
			name = strings.TrimSpace(name)
			parentDN = strings.TrimSpace(parentDN)
			if name == "" {
				return fmt.Errorf("--name is required")
			}
			if len(name) > 20 {
				return fmt.Errorf("--name too long: user sAMAccountName must be <= 20 characters")
			}
			if pass != "" && strings.TrimSpace(pass) == "" {
				return fmt.Errorf("--pass cannot be only whitespace")
			}
			if parentDN == "" {
				parentDN = fmt.Sprintf("CN=Users,%s", common.baseDN)
			}

			newDN := fmt.Sprintf("CN=%s,%s", name, parentDN)
			p.Infof("Creating user: %s\n", newDN)
			return withClient(cmd, *common, func(client *adws.WSClient) error {
				_, err := client.WSTransferAddUser(parentDN, name, pass, enabled)
				if err != nil {
					return err
				}
				if common.jsonOutput {
					p.PrintJSON(map[string]any{"status": "ok", "op": "create", "dn": newDN})
				} else {
					p.Donef("Created %s\n", newDN)
				}
				return nil
			})
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "Username (CN)")
	cmd.Flags().StringVar(&pass, "pass", "", "Password to set for the user account (optional; if empty the user is created disabled)")
	cmd.Flags().StringVar(&parentDN, "parent-dn", "", "Parent container DN (default: CN=Users,<basedn>)")
	cmd.Flags().BoolVar(&enabled, "enabled", true, "Enable the user (only applies when --pass is provided)")
	_ = cmd.MarkFlagRequired("name")
	return cmd
}

func newCreateGroupCmd(common *commonOptions) *cobra.Command {
	var name string
	var groupType string
	var parentDN string

	cmd := &cobra.Command{
		Use:   "group",
		Short: "Create a group",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := normalizeCommonOptions(common); err != nil {
				return err
			}
			p := NewPrinter(cmd.OutOrStdout(), common.noColor, common.jsonOutput)
			name = strings.TrimSpace(name)
			groupType = strings.TrimSpace(groupType)
			parentDN = strings.TrimSpace(parentDN)
			if name == "" {
				return fmt.Errorf("--name is required")
			}
			gt, err := normalizeGroupType(groupType)
			if err != nil {
				return err
			}
			if parentDN == "" {
				parentDN = fmt.Sprintf("CN=Users,%s", common.baseDN)
			}

			newDN := fmt.Sprintf("CN=%s,%s", name, parentDN)
			p.Infof("Creating group: %s\n", newDN)
			return withClient(cmd, *common, func(client *adws.WSClient) error {
				_, err := client.WSTransferAddGroup(parentDN, name, gt)
				if err != nil {
					return err
				}
				if common.jsonOutput {
					p.PrintJSON(map[string]any{"status": "ok", "op": "create", "dn": newDN})
				} else {
					p.Donef("Created %s\n", newDN)
				}
				return nil
			})
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "Group name (CN)")
	cmd.Flags().StringVar(&groupType, "type", "GlobalSecurity", "Group type: GlobalSecurity|GlobalDistribution|DomainLocalSecurity|DomainLocalDistribution|UniversalSecurity|UniversalDistribution (or a numeric value)")
	cmd.Flags().StringVar(&parentDN, "parent-dn", "", "Parent container DN (default: CN=Users,<basedn>)")
	_ = cmd.MarkFlagRequired("name")
	return cmd
}

func newCreateOUCmd(common *commonOptions) *cobra.Command {
	var name string
	var parentDN string

	cmd := &cobra.Command{
		Use:   "ou",
		Short: "Create an OU",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := normalizeCommonOptions(common); err != nil {
				return err
			}
			p := NewPrinter(cmd.OutOrStdout(), common.noColor, common.jsonOutput)
			name = strings.TrimSpace(name)
			parentDN = strings.TrimSpace(parentDN)
			if name == "" {
				return fmt.Errorf("--name is required")
			}
			if parentDN == "" {
				parentDN = common.baseDN
			}

			newDN := fmt.Sprintf("OU=%s,%s", name, parentDN)
			p.Infof("Creating OU: %s\n", newDN)
			return withClient(cmd, *common, func(client *adws.WSClient) error {
				_, err := client.WSTransferAddOU(parentDN, name)
				if err != nil {
					return err
				}
				if common.jsonOutput {
					p.PrintJSON(map[string]any{"status": "ok", "op": "create", "dn": newDN})
				} else {
					p.Donef("Created %s\n", newDN)
				}
				return nil
			})
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "OU name")
	cmd.Flags().StringVar(&parentDN, "parent-dn", "", "Parent container DN (default: <basedn>)")
	_ = cmd.MarkFlagRequired("name")
	return cmd
}

func newCreateContainerCmd(common *commonOptions) *cobra.Command {
	var name string
	var parentDN string

	cmd := &cobra.Command{
		Use:   "container",
		Short: "Create a container",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := normalizeCommonOptions(common); err != nil {
				return err
			}
			p := NewPrinter(cmd.OutOrStdout(), common.noColor, common.jsonOutput)
			name = strings.TrimSpace(name)
			parentDN = strings.TrimSpace(parentDN)
			if name == "" {
				return fmt.Errorf("--name is required")
			}
			if parentDN == "" {
				parentDN = common.baseDN
			}

			newDN := fmt.Sprintf("CN=%s,%s", name, parentDN)
			p.Infof("Creating container: %s\n", newDN)
			return withClient(cmd, *common, func(client *adws.WSClient) error {
				_, err := client.WSTransferAddContainer(parentDN, name)
				if err != nil {
					return err
				}
				if common.jsonOutput {
					p.PrintJSON(map[string]any{"status": "ok", "op": "create", "dn": newDN})
				} else {
					p.Donef("Created %s\n", newDN)
				}
				return nil
			})
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "Container name (CN)")
	cmd.Flags().StringVar(&parentDN, "parent-dn", "", "Parent container DN (default: <basedn>)")
	_ = cmd.MarkFlagRequired("name")
	return cmd
}

func newAttrCmd(common *commonOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "attr",
		Short:   "Modify an attribute via WS-Transfer Put (IMDA ModifyRequest)",
		Aliases: []string{"a"},
	}

	cmd.AddCommand(newAttrOpCmd(common, "add"))
	cmd.AddCommand(newAttrOpCmd(common, "replace"))
	cmd.AddCommand(newAttrOpCmd(common, "delete"))
	return cmd
}

func newAttrOpCmd(common *commonOptions, op string) *cobra.Command {
	var dn string
	var attr string
	var valuesCSV string

	cmd := &cobra.Command{
		Use:   op,
		Short: fmt.Sprintf("%s attribute values", op),
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := normalizeCommonOptions(common); err != nil {
				return err
			}
			p := NewPrinter(cmd.OutOrStdout(), common.noColor, common.jsonOutput)
			dn = strings.TrimSpace(dn)
			attr = strings.TrimSpace(attr)
			if dn == "" {
				return fmt.Errorf("--dn is required")
			}
			if attr == "" {
				return fmt.Errorf("--attr is required")
			}
			values := splitCSVValues(valuesCSV)
			if op != "delete" && len(values) == 0 {
				return fmt.Errorf("--value is required for %s", op)
			}
			return withClient(cmd, *common, func(client *adws.WSClient) error {
				if err := client.WSTransferModifyAttribute(dn, op, attr, values); err != nil {
					return err
				}
				if common.jsonOutput {
					p.PrintJSON(map[string]any{"status": "ok", "op": op, "dn": dn, "attr": attr})
				} else {
					p.Donef("Updated %s\n", dn)
				}
				return nil
			})
		},
	}

	cmd.Flags().StringVar(&dn, "dn", "", "Target Distinguished Name")
	cmd.Flags().StringVar(&attr, "attr", "", "Attribute name (e.g. description)")
	cmd.Flags().StringVar(&valuesCSV, "value", "", "Comma-separated value(s)")
	_ = combineErrors(cmd.MarkFlagRequired("dn"), cmd.MarkFlagRequired("attr"))
	return cmd
}

func normalizeGroupType(groupType string) (string, error) {
	s := strings.TrimSpace(groupType)
	if s == "" {
		return "-2147483646", nil
	}
	if isNumericString(s) {
		return s, nil
	}

	sLower := strings.ToLower(s)
	switch sLower {
	case "globalsecurity", "global_security", "global-security":
		return "-2147483646", nil
	case "globaldistribution", "global_distribution", "global-distribution":
		return "2", nil
	case "domainlocalsecurity", "domain_local_security", "domain-local-security":
		return "-2147483644", nil
	case "domainlocaldistribution", "domain_local_distribution", "domain-local-distribution":
		return "4", nil
	case "universalsecurity", "universal_security", "universal-security":
		return "-2147483640", nil
	case "universaldistribution", "universal_distribution", "universal-distribution":
		return "8", nil
	default:
		return "", fmt.Errorf("unknown group type %q", groupType)
	}
}

func isNumericString(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	if s[0] == '+' || s[0] == '-' {
		s = s[1:]
		if s == "" {
			return false
		}
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func domainToDN(domain string) string {
	parts := []string{}
	for _, part := range splitDomain(domain) {
		parts = append(parts, fmt.Sprintf("DC=%s", part))
	}
	return joinStrings(parts, ",")
}

func splitDomain(domain string) []string {
	result := []string{}
	current := ""
	for _, c := range domain {
		if c == '.' {
			if current != "" {
				result = append(result, current)
				current = ""
			}
		} else {
			current += string(c)
		}
	}
	if current != "" {
		result = append(result, current)
	}
	return result
}

func joinStrings(parts []string, sep string) string {
	if len(parts) == 0 {
		return ""
	}
	result := parts[0]
	for i := 1; i < len(parts); i++ {
		result += sep + parts[i]
	}
	return result
}

func newMexCmd(common *commonOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "mex",
		Short: "Fetch ADWS service metadata (unauthenticated MEX endpoint)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			dc := strings.TrimSpace(common.dcAddr)
			if dc == "" {
				return fmt.Errorf("--dc is required")
			}
			p := NewPrinter(cmd.OutOrStdout(), common.noColor, common.jsonOutput)
			client, err := newClient(*common)
			if err != nil {
				return err
			}
			meta, err := client.GetMetadata()
			if err != nil {
				return err
			}
			p.Successf("Endpoints: %d\n", len(meta.Endpoints))
			for _, ep := range meta.Endpoints {
				if common.jsonOutput {
					p.PrintJSON(map[string]any{"address": ep.Address, "authType": ep.AuthType, "identity": ep.Identity})
				} else {
					p.Donef("  %-45s  auth=%-9s  identity=%s\n",
						ep.Address, ep.AuthType, ep.Identity)
				}
			}
			return nil
		},
	}
}
