package etconfig

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/xukgo/gsaber/utils/fileUtil"
	"github.com/xukgo/gsaber/utils/stringUtil"
	"go.etcd.io/etcd/api/v3/mvccpb"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
)

type PredefEndpoint struct {
	Endpoints []string
	UserName  string
	Password  string
}
type Repo struct {
	locker *sync.RWMutex
	config *ConfRoot
	//localDict map[string]string
	client         *clientv3.Client //etcd客户端
	predefEndpoint *PredefEndpoint
}

func (this *Repo) WithPredefEndpoint(s *PredefEndpoint) {
	this.predefEndpoint = s
}
func (this *Repo) FormatConfigDescription() string {
	str := fmt.Sprintf("server:%s;", this.config.FormatEndpoints())
	return str
}

func (this *Repo) InitFromXmlPath(path string, matchHandlers []MatchVarHandler) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	return this.InitFromReader(file, matchHandlers)
}

func (this *Repo) InitFromReader(srcReader io.Reader, matchHandlers []MatchVarHandler) error {
	conf, err := ConfigUnmarshalFromReader(srcReader)
	if err != nil {
		return err
	}

	errMsg := conf.CheckValid()
	if len(errMsg) > 0 {
		return fmt.Errorf("配置格式错误:%s", errMsg)
	}

	err = fillHandler(conf, matchHandlers)

	this.locker = new(sync.RWMutex)
	//this.localDict = make(map[string]string)
	this.config = conf
	if this.predefEndpoint != nil {
		this.config.Endpoints = this.predefEndpoint.Endpoints
		this.config.Local.Authorization.UserName = this.predefEndpoint.UserName
		this.config.Local.Authorization.Password = this.predefEndpoint.Password
	}

	return this.initParam()
}
func ConfigUnmarshalFromReader(srcReader io.Reader) (*ConfRoot, error) {
	var reader *bufio.Reader
	reader = bufio.NewReader(srcReader)
	buff := make([]byte, 0, 4096)
	if reader == nil {
		return nil, fmt.Errorf("reader is invalid nil")
	}
	for {
		line, err := reader.ReadBytes('\n')
		if err == io.EOF {
			buff = append(buff, line...)
			break
		}
		if err != nil {
			return nil, err
		}
		buff = append(buff, line...)
	}

	conf := new(ConfRoot)
	err := conf.FillWithXml(buff)
	if err != nil {
		return nil, err
	}
	return conf, nil
}

func fillHandler(conf *ConfRoot, handlers []MatchVarHandler) error {
	for idx := range conf.SubscribeVars {
		subVar := &conf.SubscribeVars[idx]
		handler := findHandlerByName(handlers, subVar.HandlerName)
		if handler == nil {
			return fmt.Errorf("cannot find handler by name:%s", subVar.HandlerName)
		}
		subVar.Handler = handler
	}
	return nil
}

func findHandlerByName(handlers []MatchVarHandler, name string) func(dataId, data string) {
	for _, m := range handlers {
		if strings.EqualFold(m.Name, name) {
			return m.Handler
		}
	}
	return nil
}

func (this *Repo) initParam() error {
	var err error
	if this.config == nil {
		return fmt.Errorf("conf is nil")
	}
	//conf := this.config
	//procs := runtime.GOMAXPROCS(0)
	//if procs > 4 {
	//	procs = 4
	//}

	tlsConfig, err := this.initTlsConfig()
	if err != nil {
		return err
	}
	clicfg := clientv3.Config{
		Username:    this.config.Local.Authorization.UserName,
		Password:    this.config.Local.Authorization.Password,
		Endpoints:   this.config.Endpoints,
		DialTimeout: time.Duration(this.config.Local.Timeout) * time.Millisecond,
		TLS:         tlsConfig,
	}

	this.client, err = clientv3.New(clicfg)
	if err != nil {
		return err
	}

	for _, subs := range this.config.SubscribeVars {
		key := fmt.Sprintf("%s.%s", this.config.Local.NameSpaceID, subs.ID)
		tctx, cancel := context.WithTimeout(context.TODO(), time.Duration(this.config.Local.Timeout)*time.Millisecond)
		getResponse, err := this.client.Get(tctx, key)
		cancel()
		if err != nil {
			log.Printf("client get error:%s;%s\n", key, err.Error())
			return err
		}
		for _, kv := range getResponse.Kvs {
			content := kv.Value
			subs.Handler(key, stringUtil.NoCopyBytes2String(content))
		}
	}

	go this.watchSubs(this.config.Local.NameSpaceID, this.config.SubscribeVars)
	return nil
}

func (this *Repo) initTlsConfig() (*tls.Config, error) {
	tlsConf := this.config.Local.ClientTls
	if tlsConf == nil {
		return nil, nil
	}
	// 加载CA证书
	caCert, err := os.ReadFile(fileUtil.GetAbsUrl(tlsConf.CaFilePath))
	if err != nil {
		return nil, fmt.Errorf("failed to read CA cert: %v", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to append CA cert to pool")
	}

	// 加载客户端证书和密钥
	clientCert, err := tls.LoadX509KeyPair(fileUtil.GetAbsUrl(tlsConf.CertFilePath), fileUtil.GetAbsUrl(tlsConf.KeyFilePath))
	if err != nil {
		return nil, fmt.Errorf("failed to load client cert and key: %v", err)
	}

	// Custom CA validation logic to skip IP SAN check
	customVerify := func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return err
		}

		intermediates := x509.NewCertPool()
		for _, ic := range rawCerts[1:] {
			intermediateCert, err := x509.ParseCertificate(ic)
			if err != nil {
				return err
			}
			intermediates.AddCert(intermediateCert)
		}

		opts := x509.VerifyOptions{
			Roots:         caCertPool,
			Intermediates: intermediates,
		}

		chains, err := cert.Verify(opts)
		if err != nil {
			return err
		}

		// Optional: Further verify certificate attributes here
		// For example, verifying the Common Name
		for _, chain := range chains {
			for _, c := range chain {
				if !strings.HasPrefix(c.Subject.CommonName, "etcd") {
					return fmt.Errorf("unexpected common name: %s", c.Subject.CommonName)
				}
			}
		}

		return nil
	}

	// 手动创建 tls.Config
	tlsConfig := &tls.Config{
		Certificates:          []tls.Certificate{clientCert},
		RootCAs:               caCertPool,
		InsecureSkipVerify:    true, // Skip the default verification
		VerifyPeerCertificate: customVerify,
	}
	return tlsConfig, nil
}

func (this *Repo) Publish(id, content string) error {
	if this.client == nil {
		return fmt.Errorf("configClient is nil")
	}
	key := fmt.Sprintf("%s.%s", this.config.Local.NameSpaceID, id)
	ctx, _ := context.WithTimeout(context.Background(), time.Second*3)
	_, err := this.client.Put(ctx, key, content)
	if err != nil {
		return err
	}
	return err
}

func (this *Repo) watchSubs(ns string, vars []SubscribeVar) {
	servicePrefix := fmt.Sprintf("%s.", ns)

	for {
		watchChan := this.client.Watch(clientv3.WithRequireLeader(context.TODO()), servicePrefix, clientv3.WithPrefix())
		if watchChan == nil {
			time.Sleep(time.Second)
			continue
		}

		for watchResponse := range watchChan {
			this.updateByEvents(servicePrefix, vars, watchResponse.Events)
		}
	}
}

func (this *Repo) updateByEvents(prefix string, vars []SubscribeVar, events []*clientv3.Event) {
	for _, event := range events {
		switch event.Type {
		case mvccpb.PUT:
			tid := event.Kv.Key[len(prefix):]
			selectVar := findVarFromVarsById(vars, tid)
			if selectVar == nil {
				break
			}
			selectVar.Handler(stringUtil.NoCopyBytes2String(event.Kv.Key), stringUtil.NoCopyBytes2String(event.Kv.Value))
			break
		case mvccpb.DELETE:
			tid := event.Kv.Key[len(prefix):]
			selectVar := findVarFromVarsById(vars, tid)
			if selectVar == nil {
				break
			}
			selectVar.Handler(stringUtil.NoCopyBytes2String(event.Kv.Key), "")
			break
		default:
			break
		}
	}
}

func findVarFromVarsById(vars []SubscribeVar, tid []byte) *SubscribeVar {
	for idx := range vars {
		if vars[idx].ID == stringUtil.NoCopyBytes2String(tid) {
			return &vars[idx]
		}
	}
	return nil
}

/*
func (this *Repo) Subscribe(block bool) error {
	if this.config.Local.OfflineMode {
		return this.subscribeOffline()
	}

	if block {
		return this.subscribeOnline()
	}

	go this.subscribeOnline()
	return nil
}

func (this *Repo) subscribeOffline() error {
	for _, svar := range this.config.SubscribeVars {
		if svar.CheckBlur() {
			continue
		}
		content, err := this.configClient.GetConfig(vo.ConfigParam{
			DataId: svar.ID,
			Group:  svar.Group})
		if err != nil {
			return fmt.Errorf("get config error:group[%s] dataID[%s]; %w", svar.Group, svar.ID, err)
		}

		k := this.formatVarKey(svar.Group, svar.ID)
		this.addVar(k, content)
		handler := svar.Handler
		if handler != nil {
			handler(svar.Group, svar.ID, content)
		}
	}
	return nil
}

func (this *Repo) subscribeOnline() error {
	var err error
	dict := make(map[string]SubscribeVar)

	locker := new(sync.Mutex)
	list := make([]string, 0, 32)
	for _, svar := range this.config.SubscribeVars {
		//精确查找
		if !svar.CheckBlur() {
			k := this.formatVarKey(svar.Group, svar.ID)
			_, find := dict[k]
			if find {
				continue
			}
			dict[k] = svar
			h := svar.Handler
			err = this.configClient.ListenConfig(vo.ConfigParam{
				DataId: svar.ID,
				Group:  svar.Group,
				OnChange: func(namespace, group, dataId, data string) {
					k := this.formatVarKey(group, dataId)
					this.addVar(k, data)
					if h != nil {
						h(group, dataId, data)
					}

					locker.Lock()
					list = append(list, k)
					locker.Unlock()
				},
			})
			if err != nil {
				return fmt.Errorf("listen config error:group[%s] dataID[%s]; %w", svar.Group, svar.ID, err)
			}
			continue
		}

		vars := make([]model.ConfigItem, 0, 64)
		pageIndex := 1
		for {
			//模糊查找
			configPage, err := this.configClient.SearchConfig(vo.SearchConfigParam{
				Search:   "blur",
				DataId:   svar.ID,
				Group:    svar.Group,
				PageNo:   pageIndex,
				PageSize: 1000,
			})
			if err != nil {
				return err
			}
			vars = append(vars, configPage.PageItems...)
			if len(configPage.PageItems) < 1000 {
				break
			}
			pageIndex++
		}

		for _, item := range vars {
			k := this.formatVarKey(item.Group, item.DataId)
			_, find := dict[k]
			if find {
				continue
			}
			dict[k] = svar
			h := svar.Handler
			err = this.configClient.ListenConfig(vo.ConfigParam{
				DataId: svar.ID,
				Group:  svar.Group,
				OnChange: func(namespace, group, dataId, data string) {
					k := this.formatVarKey(group, dataId)
					this.addVar(k, data)
					if h != nil {
						h(group, dataId, data)
					}

					locker.Lock()
					list = append(list, k)
					locker.Unlock()
				},
			})
			if err != nil {
				return fmt.Errorf("listen config error:group[%s] dataID[%s]; %w", svar.Group, svar.ID, err)
			}
		}
	}

	for k, v := range dict {
		locker.Lock()
		index := arrayUtil.ContainsString(list, k)
		locker.Unlock()
		if index >= 0 {
			continue
		}
		content, err := this.configClient.GetConfig(vo.ConfigParam{
			DataId: v.ID,
			Group:  v.Group})
		if err != nil {
			return fmt.Errorf("get config error:group[%s] dataID[%s]; %w", v.Group, v.ID, err)
		}

		this.addVar(k, content)
		h := v.Handler
		if h != nil {
			h(v.Group, v.ID, content)
		}
	}
	return nil
}

func (this *Repo) checkVarExist(group, id string) bool {
	this.locker.RLock()
	_, find := this.localDict[this.formatVarKey(group, id)]
	if find {
		this.locker.RUnlock()
		return true
	}
	this.locker.RUnlock()
	return false
}

func (this *Repo) getVar(gourp, id string) string {
	this.locker.RLock()
	v, find := this.localDict[this.formatVarKey(gourp, id)]
	this.locker.RUnlock()
	if !find {
		return ""
	}
	return v
}

func (this *Repo) addVar(k string, content string) {
	this.locker.Lock()
	this.localDict[k] = content
	this.locker.Unlock()
}

func (this *Repo) formatVarKey(group, id string) string {
	k := fmt.Sprintf("%s::%s", group, id)
	return k
}
*/
