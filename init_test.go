package etconfig

import (
	"fmt"
	"testing"
)

func TestInitFromFIle(t *testing.T) {
	vhs := make([]MatchVarHandler, 0, 1)
	vhs = append(vhs, InitMatchVarHandler("appHandler1", updateAppConfig))

	repo := new(Repo)
	err := repo.InitFromXmlPath("application.xml", vhs)
	if err != nil {
		t.FailNow()
	}
}

func updateAppConfig(id, data string) {
	fmt.Printf("get update data from: %s\n%s\n", id, data)
}
