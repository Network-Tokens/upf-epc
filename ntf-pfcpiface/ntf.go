package main

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/golang/protobuf/ptypes"
	pb "github.com/omec-project/upf-epc/pfcpiface/bess_pb"
	"ntf_pb"
)

type ntfUserCentricToken struct {
	tokenAppId    uint32
	encryptionKey string
	dscp          uint32
}

type pfdRuleEntry struct {
	upf        *upf
	dpid       uint32
	pfdAppId   uint32
	config     *ntfUserCentricToken
}

type PfdRules struct {
	rules map[uint32]*pfdRuleEntry
	upf     *upf
	dpid    uint32
}

func NewPfdRules(upf *upf, dpid uint32) *PfdRules {
	log.Println("NewPfdRules")
	config := new(PfdRules)
	config.rules = make(map[uint32]*pfdRuleEntry)
	config.upf = upf
	config.dpid = dpid
	return config
}

func (pfdRules *PfdRules) NewPfdRule(pfdAppId uint32) *pfdRuleEntry {
	log.Println("NewPfdRule")
	entry := new(pfdRuleEntry)
	entry.upf = pfdRules.upf
	entry.dpid = pfdRules.dpid
	entry.pfdAppId = pfdAppId
    pfdRules.rules[pfdAppId] = entry
	return entry
}

func (entry *pfdRuleEntry) setConfig(config *ntfUserCentricToken) {
	log.Println("pfdRuleEntry.setConfig()")

	create := false
	if entry.config == nil {
		create = true
	}

	entry.config = config

	if create {
		entry.createBessEntry(entry.upf)
	} else {
		entry.updateBessEntry(entry.upf)
	}
}

func (pfdRules *PfdRules) UpdateAppConfig(pfdAppId uint32, config string) {
	log.Println("PfdRules.UpdateAppConfig()")

	var tokenConfig ntfUserCentricToken
	json.Unmarshal([]byte(config), &tokenConfig)

	entry, ok := pfdRules.rules[pfdAppId]
	if !ok {
		entry = pfdRules.NewPfdRule(pfdAppId)
	}

	entry.setConfig(&tokenConfig)
}

func (entry *pfdRuleEntry) createBessEntry(upf *upf) error {
	log.Println("pfdRuleEntry.createBessEntry(entry.pfdAppId=", entry.pfdAppId, ")")
	if err := upf.pauseAll(); err != nil {
		return err
	}

	token := ntf_pb.UserCentricNetworkToken{
		AppId:         entry.config.tokenAppId,
		EncryptionKey: entry.config.encryptionKey,
	}

	arg := ntf_pb.NtfEntryCreateArg{
		Dpid:      entry.dpid,
		Token:     &token,
		SetDscp:   &ntf_pb.NtfEntryCreateArg_Dscp{entry.config.dscp},
		SetRuleId: &ntf_pb.NtfEntryCreateArg_RuleId{entry.pfdAppId},
	}

	any, err := ptypes.MarshalAny(&arg)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	cr, err := upf.client.ModuleCommand(ctx, &pb.CommandRequest{
		Name: "ntf0",
		Cmd:  "entry_create",
		Arg:  any,
	})
	log.Println("entry_create:", cr)

	if err != nil {
		return err
	}
	log.Println("ntf.entry_create():", cr)

	if err = upf.resumeAll(); err != nil {
		return err
	}

	return nil
}

type ntfError struct {
	reason string
}

func (e *ntfError) Error() string {
	return e.reason
}

func (config *pfdRuleEntry) updateBessEntry(upf *upf) error {
	log.Println("TODO: updateBessEntry")
	return &ntfError{"TODO"}
}

func (config *pfdRuleEntry) deleteBessEntry(upf *upf) error {
	log.Println("TODO: deleteBessEntry")
	return &ntfError{"TODO"}
}
