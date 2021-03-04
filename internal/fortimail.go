package internal

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/hiddengearz/fgt-block-phishing/internal/encrypt"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

type Fortimails []Fortimail

type Fortimail struct {
	Url      string
	Username string
	Password string
	Cookie   http.Cookie
}

type LoginRequest struct {
	Name     string `json:"name"`
	Password string `json:"password"`
}

func (u *Fortimail) Login() error {
	data := &LoginRequest{
		Name:     u.Username,
		Password: u.Password,
	}

	json, err := json.Marshal(data)
	if err != nil {
		log.Error(err.Error())
		return err
	}

	url := u.Url + "/api/v1/AdminLogin/"
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(json))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Error(err.Error())
		return err
	}
	if resp.StatusCode != 200 {
		data, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Error(err.Error())
			return err
		}
		return fmt.Errorf("Error login API returned: " + string(data))
	}
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "APSCOOKIE" && cookie.Value != "" {
			u.Cookie = *cookie

			fmt.Println(u)
			return nil
		}
	}

	return fmt.Errorf("Unable to retrieve cookie for user: " + u.Username + " at fortimail: " + url)

}

func (u *Fortimail) GetBlackList() error {
	type Tmp struct {
		ReqAction  string
		ExtraParam string
	}
	data := &Tmp{
		ReqAction:  "1",
		ExtraParam: "whitelist",
	}

	json, err := json.Marshal(data)
	if err != nil {
		log.Error(err.Error())
		return err
	}

	url := u.Url + "/api/v1/UserMaillist/system/"
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(json))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&u.Cookie)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Error(err.Error())
		return err
	}

	g, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Error(err.Error())
		return err
	}
	fmt.Println(string(g))

	return nil
}

func (u *Fortimail) AddToBlackList(email string) error {
	type Tmp struct {
		Listitems  string
		ExtraParam string
	}

	data := &Tmp{
		Listitems:  base64.StdEncoding.EncodeToString([]byte(email)),
		ExtraParam: "blacklist",
	}

	json, err := json.Marshal(data)
	if err != nil {
		log.Error(err.Error())
		return err
	}

	url := u.Url + "/api/v1/UserMaillist/system/"
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(json))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&u.Cookie)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Error(err.Error())
		return err
	}

	g, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Error(err.Error())
		return err
	}
	fmt.Println(string(g))

	return nil
}

func (u *Fortimail) AddToDB(key string) error {
	var fortimails Fortimails

	encString := viper.GetString("Fortimails")
	if encString != "" {
		data, err := encrypt.DecryptData(encString, key)
		if err != nil {
			log.Error(err)
			return err
		}
		err = json.Unmarshal(data, &fortimails)
		if err != nil {
			log.Error(err)
			return err
		}

	}
	for _, fortimail := range fortimails {
		if u.Url == fortimail.Url {
			return fmt.Errorf("Entry already exists for " + u.Url + ". Please remove first before adding it again \"remove fortimail ...\"")
		}
	}

	err := u.Login()
	if err != nil {
		log.Error("Unable to log into " + u.Url + " with provided credentials")
		return err
	}

	fortimails = append(fortimails, *u)

	b, err := json.Marshal(fortimails)
	if err != nil {
		log.Error(err)
		return err
	}

	encData, err := encrypt.EncryptData(b, key)
	if err != nil {
		log.Error(err)
		return err
	}

	viper.Set("Fortimails", encData)
	err = viper.WriteConfig()
	if err != nil {
		log.Error(err)
		return err
	}

	return nil
}

func GetFortimails(key string) (err error, fms Fortimails) {
	encString := viper.GetString("Fortimails")
	if encString != "" {
		data, err := encrypt.DecryptData(encString, key)
		if err != nil {
			log.Error(err)
			return err, Fortimails{}
		}
		err = json.Unmarshal(data, &fms)
		if err != nil {
			log.Error(err)
			return err, Fortimails{}
		}
		return err, fms

	}
	return fmt.Errorf("No fortimails saved"), Fortimails{}
}
