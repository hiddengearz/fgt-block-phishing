package internal

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	l "github.com/hiddengearz/fgt-block-phishing/internal/logger"
)

var (
	Fortimails []Fortimail
)

type Fortimail struct {
	Url      string
	Username string
	Password string
	Cookie   string
}

type loginRequest struct {
	name     string
	password string
}

func (u *Fortimail) Login() error {
	data := &loginRequest{
		name:     u.Username,
		password: u.Password,
	}

	json, err := json.Marshal(data)
	if err != nil {
		l.Log.Error(err.Error())
		return err
	}

	url := fortimail.Url + "/api/v1/AdminLogin/"
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(b))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		l.Log.Error(err.Error())
		return err
	}

	for _, cookie := range resp.Cookies() {
		if cookie.Name == "APSCOOKIE" && cookie.Value() != "" {
			u.Cookie == cookie.Value()
			return nil
		}
	}

	return fmt.Errorf("Unable to retrieve cookie for user: " + u.Username + " at fortimail: " + url)

}
