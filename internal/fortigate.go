package internal

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

type FortiGate struct {
	Url        string
	Token      string
	UrlFilters UrlFilterList
	IDs        []int //ids of url filters to block
}

type UrlFilterRequest struct {
	ID      string  `json:"id,omitempty"`
	Name    string  `json:"name,omitempty"`
	Entries []Entry `json:"entries,omitempty"`
}

type Entry struct {
	Type   string `json:"type,omitempty"`
	Action string `json:"action,omitempty"`
	Status string `json:"status,omitempty"`
}

type UrlFilterList struct {
	HTTPMethod string `json:"http_method"`
	Revision   string `json:"revision"`
	Results    []struct {
		ID                 int    `json:"id"`
		QOriginKey         int    `json:"q_origin_key"`
		Name               string `json:"name"`
		Comment            string `json:"comment"`
		OneArmIpsUrlfilter string `json:"one-arm-ips-urlfilter"`
		IPAddrBlock        string `json:"ip-addr-block"`
		Entries            []struct {
			ID               int    `json:"id"`
			QOriginKey       int    `json:"q_origin_key"`
			URL              string `json:"url"`
			Type             string `json:"type"`
			Action           string `json:"action"`
			Status           string `json:"status"`
			Exempt           string `json:"exempt"`
			WebProxyProfile  string `json:"web-proxy-profile"`
			ReferrerHost     string `json:"referrer-host"`
			DNSAddressFamily string `json:"dns-address-family"`
		} `json:"entries"`
	} `json:"results"`
	Vdom       string `json:"vdom"`
	Path       string `json:"path"`
	Name       string `json:"name"`
	Status     string `json:"status"`
	HTTPStatus int    `json:"http_status"`
	Serial     string `json:"serial"`
	Version    string `json:"version"`
	Build      int    `json:"build"`
}

func (u *FortiGate) GetUrlFilters() error {

	url := u.Url + "/api/v2/cmdb/webfilter/urlfilter/?access_token=" + u.Token
	req, err := http.NewRequest("GET", url, nil)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Error(err.Error())
		fmt.Println("1")
		return err
	}

	g, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Error(err.Error())
		fmt.Println("2")
		return err
	}

	if resp.StatusCode != 200 {

		log.Debug(resp)
		log.Debug(string(g))
		fmt.Println("3")
		return fmt.Errorf(string(g))
	}

	err = json.NewDecoder(resp.Body).Decode(&u.UrlFilters)
	if err != nil {
		log.Error(err)
		fmt.Println("4")
		return err
	}

	fmt.Println("xzzz")
	fmt.Println(string(g))

	return nil

}

func (u *FortiGate) IDsToBlock() error {
	fmt.Println("Filters on", u.Url)
	for _, filter := range u.UrlFilters.Results {
		fmt.Println(filter.ID, filter.Name)
	}

	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Print("Enter the ID of the URL filters to block. Enter q or quit when complete: ")
		text, _ := reader.ReadString('\n')
		text = strings.Replace(text, "\n", "", -1)

		if text == "q" || text == "quit" {
			break
		}

		i, err := strconv.Atoi(text)
		if err != nil {
			fmt.Println(text, "isnt a ID")
		} else {
			u.IDs = append(u.IDs, i)
		}

	}

	if len(u.IDs) == 0 {
		log.Error("No id's provided")
		return fmt.Errorf("no id's provided")
	}

	return nil
}

//func (u *FortiGate) BlockURL(blockUrl string, urlType string, action string, key string) error {
func (u *FortiGate) BlockURL() error {
	type Tmp struct {
		Listitems  string
		ExtraParam string
	}
	/*
		data := &UrlFilterRequest{
			Entries: []Entry{
				Entry{
					Type:   urlType,
					Action: action,
					Status: "enable",
				},
			},
		}
	*/

	//json, err := json.Marshal(data)
	//if err != nil {
	////	log.Error(err.Error())
	//	return err
	//}

	url := u.Url + "/api/v2/cmdb/webfilter/urlfilter?access_token=" + u.Token
	//req, err := http.NewRequest("POST", url, bytes.NewBuffer(json))
	req, err := http.NewRequest("GET", url, nil)
	req.Header.Set("Content-Type", "application/json")

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
