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
	LeakWay        string
}

type RoleDetail struct {
	Id          string   `json:"id"`
	Name        string   `json:"name"`
	Mode        float64  `json:"mode"`
	Description string   `json:"description"`
	UserIds     []string `json:"user_ids"` // 角色成员
}

type UserInfo struct {
	DeviceName string
	ClientIp   string
}
