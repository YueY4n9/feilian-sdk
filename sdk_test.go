package feilian_sdk

import (
	"github.com/YueY4n9/gotools/echo"
	"testing"
	"time"
)

func newClient() FeilianClient {
	address := "https://192.168.200.217:8443"
	appId := "rLpyGwqskHwSIZOWjgvA"
	appKey := "LnrEJhgWqZwBVYAiOcXEpIHzzAljuDVTwhBHWvhf"
	return NewClient(address, appId, appKey)
}

func TestFeilianClient_GetSecurityEvents(t *testing.T) {
	client := newClient()
	now := time.Now()
	lastMinuteEnd := time.Date(now.Year(), now.Month(), now.Day(), now.Hour(), now.Minute(), 0, 0, now.Location()).Add(-0 * time.Minute)
	lastMinuteStart := lastMinuteEnd.Add(-1 * time.Minute)
	startTime := lastMinuteStart.Unix()
	endTime := lastMinuteEnd.Unix()
	events, err := client.ListSecurityEvents(startTime, endTime)
	if err != nil {
		t.Fatal(err)
	}
	echo.Json(events)
	for _, event := range events {
		fileUrl, err := client.ListSecurityFileUrl("file", event.EventId)
		if err != nil {
			t.Fatal(err)
		}
		echo.Json(fileUrl)
		screenshotUrl, err := client.ListSecurityFileUrl("screenshot", event.EventId)
		if err != nil {
			t.Fatal(err)
		}
		echo.Json(screenshotUrl)
	}
}

func TestFeilianClient_ListUserIdsByRoleId(t *testing.T) {
	client := newClient()
	roleIds, err := client.ListRoleIdsByRoleName("OneDrive")
	if err != nil {
		t.Fatal(err)
	}
	echo.Json(roleIds)
	for _, roleId := range roleIds {
		userIds, err := client.ListUserIdsByRoleId(roleId)
		if err != nil {
			t.Fatal(err)
		}
		echo.Json(userIds)
	}
}
