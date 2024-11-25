package feilian_sdk

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/YueY4n9/gotools/echo"
	"github.com/pkg/errors"
)

type FeilianClient interface {
	GetToken() string
	ListSecurityEvents(startTime, endTime int64) ([]*SecurityEvent, error)
	ListSecurityFileUrl(fileType, eventId string) ([]string, error)
	ListRolesByRoleName(name string) ([]RoleDetail, error)
	ListRoleIdsByRoleName(name string) ([]string, error)
	ListUserIdsByRoleId(roleId string) ([]string, error)
	ListUserDevice(limit, offset int) (map[string]interface{}, error)
}

type feilianClient struct {
	Address   string
	AppId     string
	AppSecret string

	mu     sync.Mutex
	token  string
	expiry time.Time
}

func NewClient(address, appId, appKey string) FeilianClient {
	return &feilianClient{
		Address:   address,
		AppId:     appId,
		AppSecret: appKey,
	}
}

// GetToken return client.token, if getToken return error, return ""
func (c *feilianClient) GetToken() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if time.Now().After(c.expiry.Add(-3 * time.Minute)) { // 3 minutes buffer to avoid race conditions
		newToken, err := c.getToken()
		if err != nil {
			return ""
		}
		c.token = newToken
		c.expiry = time.Now().Add(30 * time.Minute)
		return newToken
	}
	return c.token
}

func (c *feilianClient) getToken() (string, error) {
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
	echo.Json("refresh token")
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
		req.Header.Set("Authorization", c.GetToken())
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
				FileMd5:        item.(map[string]interface{})["file_info"].(map[string]interface{})["md_5"].(string),
				FileSize:       item.(map[string]interface{})["file_info"].(map[string]interface{})["size"].(float64),
				DepartmentPath: item.(map[string]interface{})["user_info"].(map[string]interface{})["department_path"].(string),
				EventType:      item.(map[string]interface{})["event_type"].(string),
				EventUnixTime:  int64(item.(map[string]interface{})["event_unix_time"].(float64)),
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
	req.Header.Set("Authorization", c.GetToken())
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

func (c *feilianClient) ListRolesByRoleName(name string) ([]RoleDetail, error) {
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
	req.Header.Set("Authorization", c.GetToken())
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
	res := make([]RoleDetail, 0)
	for _, role := range roleList {
		roleDetail := RoleDetail{
			Id:          role.(map[string]interface{})["id"].(string),
			Name:        role.(map[string]interface{})["name"].(string),
			Mode:        role.(map[string]interface{})["mode"].(int),
			Description: role.(map[string]interface{})["description"].(string),
		}
		userIds, err := c.ListUserIdsByRoleId(role.(map[string]interface{})["id"].(string))
		if err != nil {
			return nil, err
		}
		roleDetail.UserIds = userIds
		res = append(res, roleDetail)
	}
	return res, nil
}

func (c *feilianClient) ListRoleIdsByRoleName(name string) ([]string, error) {
	roleDetails, err := c.ListRolesByRoleName(name)
	if err != nil {
		return nil, err
	}
	roleIds := make([]string, 0)
	for _, roleDetail := range roleDetails {
		roleIds = append(roleIds, roleDetail.Id)
	}
	return roleIds, nil
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
		req.Header.Set("Authorization", c.GetToken())
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
		echo.Json(items)
		for _, item := range items {
			userId := item.(map[string]interface{})["user_id"].(string)
			res = append(res, userId)
		}
	}
	return res, nil
}

func (c *feilianClient) GetUserUidByMobile(mobile string) (string, error) {
	url := fmt.Sprintf("%v/api/open/v1/user/get_id", c.Address)
	payload := map[string]string{
		"mobile": mobile,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		fmt.Println("Error encoding JSON:", err)
		return "", err
	}
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
	if err != nil {
		fmt.Println("Error creating request:", err)
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", c.GetToken())
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error making request:", err)
		return "", err
	}
	defer resp.Body.Close()
	fmt.Println("Response Status:", resp.Status)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response body:", err)
		return "", err
	}
	var bodyMap = make(map[string]interface{})
	err = json.Unmarshal(body, &bodyMap)
	if err != nil {
		fmt.Println("Error reading response body:", err)
		return "", err
	}
	return bodyMap["data"].(map[string]interface{})["id"].(string), nil
}

// AddVpnPermission idType 1: dept 2: user 3:role
func (c *feilianClient) AddVpnPermission(idType int, ids []string, days int) error {
	url := fmt.Sprintf("%v/api/open/v1/vpn/permission/add", c.Address)
	payload := map[string]interface{}{
		"identity_type": idType, // 1: dept 2: user 3:role
		"identity_ids":  ids,
		"days":          days,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return errors.WithStack(err)
	}
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
	if err != nil {
		return errors.WithStack(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", c.GetToken())
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Do(req)
	if err != nil {
		return errors.WithStack(err)
	}
	defer resp.Body.Close()
	return nil
}

// ListUserDevice a
func (c *feilianClient) ListUserDevice(limit, offset int) (map[string]interface{}, error) {
	url := fmt.Sprintf("%v/api/open/v1/device/search?limit=%v&offset=%v", c.Address, limit, offset)
	payload := map[string]interface{}{}
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	req, err := http.NewRequest("GET", url, bytes.NewBuffer(data))
	if err != nil {
		return nil, errors.WithStack(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", c.GetToken())
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer resp.Body.Close()
	fmt.Println("Response Status:", resp.Status)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response body:", err)
		return nil, err
	}
	var bodyMap = make(map[string]interface{})
	err = json.Unmarshal(body, &bodyMap)
	if err != nil {
		fmt.Println("Error reading response body:", err)
		return nil, err
	}
	return bodyMap, nil
}
