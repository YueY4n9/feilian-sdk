package feilian_sdk

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"github.com/pkg/errors"

	"fmt"
	"github.com/YueY4n9/gotools/echo"
	"io"
	"net/http"
	"time"
)

type FeilianClient interface {
	GetToken() (string, error)
	ListSecurityEvents(startTime, endTime int64) ([]*SecurityEvent, error)
	ListSecurityFileUrl(fileType, eventId string) ([]string, error)
	ListRoleIdsByRoleName(name string) ([]string, error)
	ListUserIdsByRoleId(roleId string) ([]string, error)
}

type feilianClient struct {
	Address   string
	AppId     string
	AppSecret string
}

func NewClient(address, appId, appKey string) FeilianClient {
	return &feilianClient{
		Address:   address,
		AppId:     appId,
		AppSecret: appKey,
	}
}

func (c *feilianClient) GetToken() (string, error) {
	url := c.Address + "/api/open/v1/token"
	payload := map[string]string{
		"access_key_id":     c.AppId,
		"access_key_secret": c.AppSecret,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", errors.WithStack(err)
	}
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
	if err != nil {
		return "", errors.WithStack(err)
	}
	req.Header.Set("Content-Type", "application/json")
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	type TokenResponse struct {
		Code    int    `json:"code"`
		Action  string `json:"action"`
		Message string `json:"message"`
		Data    struct {
			AccessToken string `json:"access_token"`
			ExpiresIn   int    `json:"expires_in"`
		} `json:"data"`
	}
	var tokenResp TokenResponse
	if err := json.Unmarshal(responseBody, &tokenResp); err != nil {
		return "", err
	}
	if tokenResp.Code != 0 {
		return "", errors.New(tokenResp.Message)
	}
	return tokenResp.Data.AccessToken, nil
}

func (c *feilianClient) ListSecurityEvents(startTime, endTime int64) ([]*SecurityEvent, error) {
	res := make([]*SecurityEvent, 0)
	for hasMore, offset, limit := true, 0, 20; hasMore; offset += limit {
		url := fmt.Sprintf("%v/api/open/v1/security/edlp/events/list?start_time=%v&end_time=%v&limit=%v&offset=%v", c.Address, startTime, endTime, limit, offset)
		payload := map[string]interface{}{}
		data, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequest("GET", url, bytes.NewBuffer(data))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		token, err := c.GetToken() // TODO 优化逻辑
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", token)
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client := &http.Client{Transport: tr}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		var bodyMap = make(map[string]interface{})
		err = json.Unmarshal(body, &bodyMap)
		if err != nil {
			return nil, err
		}
		echo.Json(bodyMap)
		if bodyMap["data"] == nil {
			return nil, errors.New("ListSecurityEvents error")
		}
		count := bodyMap["data"].(map[string]interface{})["count"]
		hasMore = count.(float64) > float64(offset+limit)
		items := bodyMap["data"].(map[string]interface{})["items"]
		if items == nil {
			return []*SecurityEvent{}, nil
		}
		for _, item := range items.([]interface{}) {
			res = append(res, &SecurityEvent{
				EventId:        item.(map[string]interface{})["event_id"].(string),
				UserId:         item.(map[string]interface{})["user_info"].(map[string]interface{})["user_id"].(string),
				UserName:       item.(map[string]interface{})["user_info"].(map[string]interface{})["full_name"].(string),
				FileName:       item.(map[string]interface{})["file_info"].(map[string]interface{})["name"].(string),
				FileType:       item.(map[string]interface{})["file_info"].(map[string]interface{})["type"].(string),
				DepartmentPath: item.(map[string]interface{})["user_info"].(map[string]interface{})["department_path"].(string),
				EventType:      item.(map[string]interface{})["event_type"].(string),
				EventTime:      time.Unix(int64(item.(map[string]interface{})["event_unix_time"].(float64)), 0).Format(time.DateTime),
				DeviceName:     item.(map[string]interface{})["device_name"].(string),
				FilePath:       item.(map[string]interface{})["file_info"].(map[string]interface{})["path"].(string),
				ActionDesc:     item.(map[string]interface{})["action_desc"].(string),
				StrategyName:   item.(map[string]interface{})["strategy_name"].(string),
			})
		}
	}
	return res, nil
}

func (c *feilianClient) ListSecurityFileUrl(fileType, eventId string) ([]string, error) {
	url := fmt.Sprintf("%v/api/open/v1/security/edlp/events/evidence/%v?event_id=%v", c.Address, fileType, eventId)
	payload := map[string]interface{}{}
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("GET", url, bytes.NewBuffer(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	token, err := c.GetToken()
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", token)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var bodyMap = make(map[string]interface{})
	err = json.Unmarshal(body, &bodyMap)
	if err != nil {
		return nil, err
	}
	if bodyMap["code"].(float64) != 0 || bodyMap["data"] == nil {
		return nil, nil
	}
	res := make([]string, 0)
	urls := bodyMap["data"].([]interface{})
	for _, item := range urls {
		res = append(res, item.(string))
	}
	return res, nil
}

func (c *feilianClient) ListRoleIdsByRoleName(name string) ([]string, error) {
	url := fmt.Sprintf("%v/api/open/v1/role/list?query=%v", c.Address, name)
	payload := map[string]interface{}{}
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("GET", url, bytes.NewBuffer(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	token, err := c.GetToken()
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", token)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var bodyMap = make(map[string]interface{})
	err = json.Unmarshal(body, &bodyMap)
	if err != nil {
		return nil, err
	}
	if bodyMap["code"].(float64) != 0 || bodyMap["data"] == nil {
		return nil, nil
	}
	roleList := bodyMap["data"].(map[string]interface{})["role_list"].([]interface{})
	echo.Json(roleList)
	res := make([]string, 0)
	for _, role := range roleList {
		res = append(res, role.(map[string]interface{})["id"].(string))
	}
	return res, nil
}

func (c *feilianClient) ListUserIdsByRoleId(roleId string) ([]string, error) {
	res := make([]string, 0)
	for hasMore, offset, limit := true, 0, 20; hasMore; offset += limit {
		url := fmt.Sprintf("%v/api/open/v1/role/get?id=%v&limit=200&offset=%v", c.Address, roleId, offset)
		payload := map[string]interface{}{}
		data, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequest("GET", url, bytes.NewBuffer(data))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		token, err := c.GetToken()
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", token)
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client := &http.Client{Transport: tr}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		var bodyMap = make(map[string]interface{})
		err = json.Unmarshal(body, &bodyMap)
		if err != nil {
			return nil, err
		}
		if bodyMap["code"].(float64) != 0 || bodyMap["data"] == nil {
			return nil, nil
		}
		count := bodyMap["data"].(map[string]interface{})["count"].(float64)
		hasMore = count > float64(offset+limit)
		items := bodyMap["data"].(map[string]interface{})["items"].([]interface{})
		for _, item := range items {
			userId := item.(map[string]interface{})["user_id"].(string)
			res = append(res, userId)
		}
	}
	return res, nil
}