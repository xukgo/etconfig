package etconfig

import (
	"encoding/xml"
	"os"
	"strings"
)

type ConfRoot struct {
	XMLName       xml.Name
	EnvDefine     EnvironmentDefine `xml:"EnvDefine"`
	Endpoints     []string          `xml:"Servers>Endpoint"` //
	Local         *LocalConf        `xml:"Local"`            //etcd连接超时时间,单秒秒
	SubscribeVars []SubscribeVar    `xml:"Subscribe>Var"`    //
}

func (this *ConfRoot) FormatEndpoints() string {
	sb := strings.Builder{}
	for idx, v := range this.Endpoints {
		sb.WriteString(v)
		if idx != len(this.Endpoints)-1 {
			sb.WriteByte(',')
		}
	}
	return sb.String()
}

func (this *ConfRoot) CheckValid() string {
	if this.Local == nil {
		return "local config is nil"
	}
	errMsg := this.Local.CheckValid()
	if len(errMsg) > 0 {
		return errMsg
	}
	if len(this.Endpoints) == 0 {
		return "Endpoint config is empty"
	}
	if len(this.SubscribeVars) == 0 {
		return "Subscribe Vars is empty"
	}
	for _, svar := range this.SubscribeVars {
		errMsg = svar.CheckValid()
		if len(errMsg) > 0 {
			return errMsg
		}
	}
	return ""
}

func (this *ConfRoot) FillWithXml(xmlContents []byte) error {
	err := xml.Unmarshal(xmlContents, this)
	if err != nil {
		return err
	}

	if len(this.EnvDefine.EtcdUrls) == 0 {
		return nil
	}
	urlstrs := os.Getenv(this.EnvDefine.EtcdUrls)
	if len(urlstrs) == 0 {
		return nil
	}
	sarr := strings.Split(urlstrs, ",")

	this.Endpoints = make([]string, 0, len(sarr))
	for _, str := range sarr {
		str = strings.TrimSpace(str)
		this.Endpoints = append(this.Endpoints, str)
	}
	if len(this.EnvDefine.EtcdNamespace) > 0 && this.Local != nil {
		namespace := os.Getenv(this.EnvDefine.EtcdNamespace)
		this.Local.NameSpaceID = namespace
	}
	return nil
}

type EnvironmentDefine struct {
	EtcdUrls      string `xml:"EtcdUrls"`
	EtcdNamespace string `xml:"EtcdNamespace"`
}

type LocalConf struct {
	AppName       string              `xml:"AppName"`
	NameSpaceID   string              `xml:"NameSpaceID"`
	Timeout       int                 `xml:"Timeout"`      //请求超时ms
	BeatInterval  int                 `xml:"BeatInterval"` //和服务器的心跳间隔ms
	Authorization ClientAuthorization `xml:"Auth"`         //
}

type ClientAuthorization struct {
	UserName string `xml:"username,attr"`
	Password string `xml:"password,attr"`
}

type SubscribeVar struct {
	ID          string                `xml:"id,attr"`
	HandlerName string                `xml:"handler,attr"`
	Handler     func(id, data string) `xml:"-"`
}

type MatchVarHandler struct {
	Name    string
	Handler func(id, data string)
}

func InitMatchVarHandler(name string, h func(id, data string)) MatchVarHandler {
	return MatchVarHandler{
		Name:    name,
		Handler: h,
	}
}

func (this LocalConf) CheckValid() string {
	if len(this.AppName) == 0 {
		return "local config AppName is empty"
	}
	if this.Timeout < 1 {
		return "local config Timeout invalid"
	}
	if this.BeatInterval < 1 {
		return "local config BeatInterval invalid"
	}
	return ""
}

func (this SubscribeVar) CheckValid() string {
	if len(this.ID) == 0 {
		return "subscribe var id is empty"
	}
	if len(this.HandlerName) == 0 {
		return "subscribe var handler is empty"
	}
	return ""
}

func (this SubscribeVar) CheckBlur() bool {
	if strings.Index(this.ID, "*") >= 0 {
		return true
	}
	return false
}
