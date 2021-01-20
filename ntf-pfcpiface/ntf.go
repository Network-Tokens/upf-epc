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
	TokenType     uint32
	EncryptionKey string
	Dscp          uint32
}

type pfdRuleEntry struct {
	upf        *upf
	pfdAppId   uint32
	config     *ntfUserCentricToken
}

type PfdRules struct {
	rules map[uint32]*pfdRuleEntry
	upf   *upf
}

func NewPfdRules(upf *upf) *PfdRules {
	log.Println("NewPfdRules")
	config := new(PfdRules)
	config.rules = make(map[uint32]*pfdRuleEntry)
	config.upf = upf
	return config
}

func (pfdRules *PfdRules) NewPfdRule(pfdAppId uint32) *pfdRuleEntry {
	log.Println("NewPfdRule")
	entry := new(pfdRuleEntry)
	entry.upf = pfdRules.upf
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

func (entry *pfdRuleEntry) clearConfig() {
	log.Println("pfdRuleEntry.clearConfig()")

	if entry.config != nil {
		entry.deleteBessEntry(entry.upf)
	}
}

func (pfdRules *PfdRules) UpdateAppConfig(pfdAppId uint32, config string) {
	log.Println("PfdRules.UpdateAppConfig()")
	log.Println("pfdAppId:", pfdAppId, " config:", config)

	var tokenConfig ntfUserCentricToken
	json.Unmarshal([]byte(config), &tokenConfig)
    log.Println("unmarshalled:", tokenConfig)

	entry, ok := pfdRules.rules[pfdAppId]
	if !ok {
		entry = pfdRules.NewPfdRule(pfdAppId)
	}

	entry.setConfig(&tokenConfig)
}

func (pfdRules *PfdRules) RemoveAppConfig(pfdAppId uint32) {
	log.Println("PfdRules.RemoveAppConfig()")
	log.Println("pfdAppId:", pfdAppId)

	entry, ok := pfdRules.rules[pfdAppId]
	if ok {
		entry.clearConfig()
	}
}

func (entry *pfdRuleEntry) createBessEntry(upf *upf) error {
	log.Println("pfdRuleEntry.createBessEntry(entry.pfdAppId=", entry.pfdAppId, ")")
	if err := upf.pauseAll(); err != nil {
		return err
	}

	token := ntf_pb.UserCentricNetworkToken{
		TokenType:     entry.config.TokenType,
		EncryptionKey: entry.config.EncryptionKey,
	}

	arg := ntf_pb.NTFEntryCreateArg{
		Token:     &token,
		SetDscp:   &ntf_pb.NTFEntryCreateArg_Dscp{entry.config.Dscp},
		SetRuleId: &ntf_pb.NTFEntryCreateArg_RuleId{entry.pfdAppId},
	}

	any, err := ptypes.MarshalAny(&arg)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	cr, err := upf.client.ModuleCommand(ctx, &pb.CommandRequest{
		Name: "ntf",
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

func (entry *pfdRuleEntry) updateBessEntry(upf *upf) error {
	log.Println("pfdRuleEntry.updateBessEntry(entry.pfdAppId=", entry.pfdAppId, ")")
	if err := upf.pauseAll(); err != nil {
		return err
	}

	token := ntf_pb.UserCentricNetworkToken{
		TokenType:     entry.config.TokenType,
		EncryptionKey: entry.config.EncryptionKey,
	}

	arg := ntf_pb.NTFEntryModifyArg{
		Token:     &token,
		SetDscp:   &ntf_pb.NTFEntryModifyArg_Dscp{entry.config.Dscp},
		SetRuleId: &ntf_pb.NTFEntryModifyArg_RuleId{entry.pfdAppId},
	}

	any, err := ptypes.MarshalAny(&arg)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	cr, err := upf.client.ModuleCommand(ctx, &pb.CommandRequest{
		Name: "ntf",
		Cmd:  "entry_modify",
		Arg:  any,
	})
	log.Println("entry_modify:", cr)

	if err != nil {
		return err
	}
	log.Println("ntf.entry_modify():", cr)

	if err = upf.resumeAll(); err != nil {
		return err
	}

	return nil
}

func (entry *pfdRuleEntry) deleteBessEntry(upf *upf) error {
	log.Println("pfdRuleEntry.deleteBessEntry(entry.pfdAppId=", entry.pfdAppId, ")")
	if err := upf.pauseAll(); err != nil {
		return err
	}

	arg := ntf_pb.NTFEntryDeleteArg{
		TokenType:     entry.config.TokenType,
	}

	any, err := ptypes.MarshalAny(&arg)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	cr, err := upf.client.ModuleCommand(ctx, &pb.CommandRequest{
		Name: "ntf",
		Cmd:  "entry_delete",
		Arg:  any,
	})
	log.Println("entry_delete:", cr)

	if err != nil {
		return err
	}
	log.Println("ntf.entry_delete():", cr)

	if err = upf.resumeAll(); err != nil {
		return err
	}

	return nil
}
