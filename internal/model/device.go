package model

import (
	"net"
	"time"
)

type DeviceType string

const (
	DeviceIOSRouter    DeviceType = "ios-router"
	DeviceIOSSwitch    DeviceType = "ios-switch"
	DeviceIOSCatalyst  DeviceType = "ios-catalyst"
	DeviceIOSXE        DeviceType = "ios-xe"
	DeviceIOSXR        DeviceType = "ios-xr"
	DeviceNXOS         DeviceType = "nxos"
	DevicePIX          DeviceType = "pix"
	DeviceASA          DeviceType = "asa"
	DeviceFWSM         DeviceType = "fwsm"
	DeviceNMP          DeviceType = "nmp"
	DeviceCatOS        DeviceType = "catos"
	DeviceCSS          DeviceType = "css"
	DeviceScreenOS     DeviceType = "screenos"
	DeviceJunos        DeviceType = "junos"
	DeviceFW1          DeviceType = "fw1"
	DevicePassport     DeviceType = "passport"
	DeviceSonicOS      DeviceType = "sonicos"
	DevicePANOS        DeviceType = "panos"
	DeviceFortiOS      DeviceType = "fortios"
	DeviceEOS          DeviceType = "eos"
	DeviceBIGIP        DeviceType = "bigip"
	DeviceUnknown      DeviceType = "unknown"
)

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "informational"
)

type DeviceConfig struct {
	DeviceType    DeviceType
	DeviceName    string
	Version       string
	Model         string
	Hostname      string
	Location      string
	EdgeDevice    bool
	SourceFile    string
	ParsedAt      time.Time
	General       GeneralConfig
	Interfaces    []Interface
	ACLs          []ACL
	SNMP          SNMPConfig
	Logging       LoggingConfig
	Banner        string
	Passwords     []PasswordEntry
	Users         []UserEntry
	Routing       RoutingConfig
	NTP           NTPConfig
	DNS           DNSConfig
	HTTP          HTTPConfig
	FTP           FTPConfig
	SSH           SSHConfig
	Telnet        TelnetConfig
	AAA           AAAConfig
	NAT           NATConfig
	VPNs          []VPNConfig
	RawLines      []string
}

type GeneralConfig struct {
	Hostname           string
	DomainName         string
	EnablePassword     string
	EnableSecret       string
	ServicePassword    string
	ExecTimeout        time.Duration
	CDPEnabled         bool
	IPSourceRouting    bool
	ProxyARP           bool
	Finger             bool
	Pad                bool
	IPBootpServer      bool
	HTTPServer         bool
	FTPServer          bool
	TelnetServer       bool
	SSHServer          bool
	IPDomainLookup     bool
	ServiceEncrypt     bool
	ServicePasswordEnc bool
	Banner             string
	UniqueBanner       bool
	MaxARP             int
	MaxRoutes          int
}

type Interface struct {
	Name         string
	Description  string
	IPAddress    net.IP
	SubnetMask   net.IPMask
	CIDR         string
	VLAN         int
	Zone         string
	State        string
	SecurityLevel int
	Switchport   bool
	AccessVLAN   int
	TrunkVLANs   []int
	ACLIn        string
	ACLOut       string
	ACLName      string
	OSPF         *OSPFInterface
	BGP          *BGPInterface
	RIP          *RIPInterface
	HSRP         *HSRPConfig
	VRRP         *VRRPConfig
	CDPEnabled   bool
	ProxyARP     bool
	Unicast      bool
	ManagementOnly bool
}

type OSPFInterface struct {
	Area       int
	ProcessID  int
	NetworkType string
	Cost       int
	DeadTimer  int
	HelloTimer int
	AuthType   string
	AuthKey    string
	Passive    bool
}

type BGPInterface struct {
	ASN        int
	NeighborIP string
	RemoteAS   int
	AuthKey    string
}

type RIPInterface struct {
	Version    int
	AuthType   string
	AuthKey    string
	Passive    bool
}

type HSRPConfig struct {
	Group    int
	Priority int
	AuthKey  string
	VirtualIP string
}

type VRRPConfig struct {
	Group    int
	Priority int
	AuthKey  string
	VirtualIP string
}

type RoutingConfig struct {
	StaticRoutes    []StaticRoute
	OSPF            *OSPFConfig
	BGP             *BGPConfig
	EIGRP           *EIGRPConfig
	RIPConfig       *RIPConfig
	DefaultRoute    string
	SourceRouting    bool
}

type StaticRoute struct {
	Destination string
	Mask        string
	NextHop     string
	Metric      int
}

type OSPFConfig struct {
	ProcessID  int
	RouterID   string
	Areas      []OSPFArea
	AuthType   string
	PassiveInterfaces []string
}

type OSPFArea struct {
	ID       int
	Type     string
	AuthType string
}

type BGPConfig struct {
	ASN            int
	RouterID       string
	Neighbors      []BGPNeighbor
	Redistribution []string
	AuthKey        string
}

type BGPNeighbor struct {
	IP        string
	RemoteAS  int
	AuthKey   string
	UpdateSrc string
}

type EIGRPConfig struct {
	ASN            int
	RouterID       string
	PassiveInterfaces []string
	AuthKey        string
	Redistribution []string
}

type RIPConfig struct {
	Version  int
	Neighbors []string
	AuthType string
	AuthKey  string
}

type ACL struct {
	Name       string
	Number     int
	Type       string
	Direction  string
	Interface  string
	Rules      []ACLRule
	Expanded   bool
	Logging    bool
}

type ACLRule struct {
	Sequence    int
	Action      string
	Protocol    string
	Source      string
	SourcePort  string
	Destination string
	DestPort    string
	Log         bool
	Enabled     bool
	Either      bool
	Established bool
	Fragments   bool
}

type SNMPConfig struct {
	Version         int
	Community       string
	ReadOnlyComm    string
	ReadWriteComm   string
	SNMPv3Users     []SNMPv3User
	Contact         string
	Location        string
	TrapServers     []string
	ACLName         string
	CommunityMap    map[string]string
	InformsEnabled  bool
}

type SNMPv3User struct {
	Username       string
	AuthProtocol   string
	AuthPassword   string
	PrivProtocol   string
	PrivPassword   string
	Access         string
}

type LoggingConfig struct {
	Enabled        bool
	ConsoleLevel   int
	BufferSize     int
	TrapLevel      int
	SyslogServers  []string
	LogBuffer      bool
	Timestamps     bool
	SequenceNums   bool
	SourceInterface string
}

type PasswordEntry struct {
	Type     string
	Username string
	Hash     string
	Decoded  string
	Weak     bool
	Dictionary bool
	MinLength int
}

type UserEntry struct {
	Username    string
	Password    string
	Privilege   int
	HashType    string
	Secret      bool
	TacacsPlus  bool
	Local       bool
}

type AAAConfig struct {
	NewModel       bool
	TacacsServer   string
	TacacsKey      string
	RadServer      string
	RadKey         string
	AuthList       string
	AuthrList      string
	AcctList       string
	LoginLocal     bool
	LoginDefault   bool
	EnableLocal     bool
	ExecTimeout    time.Duration
	MaxSessions    int
}

type NTPConfig struct {
	Servers     []NTPServer
	AuthEnabled bool
	AuthKey    string
	TrustedKey string
	Source     string
}

type NTPServer struct {
	Address  string
	Key      int
	Source   string
	Prefer   bool
	Version  int
}

type DNSConfig struct {
	Servers     []string
	DomainName  string
	NameServers []net.IP
}

type HTTPConfig struct {
	Enabled       bool
	Port          int
	SSL           bool
	SSLCert       string
	AccessClass   string
	Authentication string
}

type FTPConfig struct {
	Enabled   bool
	Port      int
	Timeout   time.Duration
	RootDir   string
}

type SSHConfig struct {
	Enabled      bool
	Version      int
	Port         int
	Timeout      time.Duration
	MaxRetries   int
	AuthRetries  int
	MaxSessions  int
	CipherList   []string
	MACList      []string
	KeyExchanges []string
	HostKey      string
}

type TelnetConfig struct {
	Enabled     bool
	Port        int
	Timeout     time.Duration
	MaxSessions int
	ACLName     string
}

type NATConfig struct {
	StaticNATs  []StaticNAT
	DynamicNATs []DynamicNAT
	PATRules    []PATRule
}

type StaticNAT struct {
	Internal string
	External string
}

type DynamicNAT struct {
	InsideNetwork  string
	OutsideNetwork string
	PoolName       string
}

type PATRule struct {
	InsideNetwork string
	Interface     string
}

type VPNConfig struct {
	Name       string
	Type       string
	Phase1     string
	Phase2     string
	Encryption string
	Hash       string
	DHGroup    int
	TunnelGroup string
}

type LineConfig struct {
	Type       string
	Number     int
	Password   string
	LoginLocal  bool
	ExecTimeout time.Duration
	TransportInput string
	TransportOutput string
	ACLName    string
}
