package feilian_sdk

type SecurityEvent struct {
	EventId        string
	UserId         string
	UserName       string
	FileName       string
	FileType       string
	FileMd5        string
	FileSize       float64
	DepartmentPath string
	EventType      string
	EventUnixTime  int64
	EventTime      string
	DeviceName     string
	FilePath       string
	ActionDesc     string
	StrategyName   string
}

type UserInfo struct {
	DeviceName string
	ClientIp   string
}
