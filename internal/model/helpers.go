package model

func (i *Interface) ACLEdge() bool {
	if i.Name == "" {
		return false
	}
	edgePrefixes := []string{"GigabitEthernet", "FastEthernet", "Ethernet", "Serial", "ATM"}
	for _, prefix := range edgePrefixes {
		if len(i.Name) >= len(prefix) && i.Name[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}

func (d *DeviceConfig) FindInterface(name string) *Interface {
	for i := range d.Interfaces {
		if d.Interfaces[i].Name == name {
			return &d.Interfaces[i]
		}
	}
	return nil
}

func (d *DeviceConfig) FindACL(name string) *ACL {
	for i := range d.ACLs {
		if d.ACLs[i].Name == name {
			return &d.ACLs[i]
		}
	}
	return nil
}

func (d *DeviceConfig) AddInterface(iface Interface) {
	d.Interfaces = append(d.Interfaces, iface)
}

func (d *DeviceConfig) AddACL(acl ACL) {
	d.ACLs = append(d.ACLs, acl)
}

func (d *DeviceConfig) AddPassword(pw PasswordEntry) {
	d.Passwords = append(d.Passwords, pw)
}

func (d *DeviceConfig) AddUser(user UserEntry) {
	d.Users = append(d.Users, user)
}

func (a *ACL) AddRule(rule ACLRule) {
	a.Rules = append(a.Rules, rule)
}

func (a *ACL) HasDenyAll() bool {
	for _, rule := range a.Rules {
		if rule.Action == "deny" && rule.Source == "any" && rule.Destination == "any" {
			return true
		}
	}
	return false
}

func (a *ACL) HasLogRules() bool {
	for _, rule := range a.Rules {
		if !rule.Log {
			return false
		}
	}
	return len(a.Rules) > 0
}

func (d *DeviceConfig) SetDefaults() {
	if d.General.ExecTimeout == 0 {
		d.General.ExecTimeout = 600000000000
	}
	if d.SNMP.Community == "" {
		d.SNMP.Community = "public"
	}
	if d.SSH.MaxSessions == 0 {
		d.SSH.MaxSessions = 5
	}
	if d.SSH.MaxRetries == 0 {
		d.SSH.MaxRetries = 3
	}
	if d.SSH.AuthRetries == 0 {
		d.SSH.AuthRetries = 3
	}
}
